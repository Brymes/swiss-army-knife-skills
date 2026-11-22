"""Playwright adapter: authenticated browser checks through a checked-in Node runner.

The adapter does not import Playwright itself.  It validates a JSON scenario, builds the
``node adapters/playwright/runner.mjs`` command and parses the runner's JSON result into
``needs_validation`` candidates.  A dry run only reads the scenario from disk; it never
starts Node, launches a browser or contacts a target.  ``check()`` inspects the host for
Node, npx, the runner and a cached Chromium build without installing anything.

Everything the runner records is metadata: step status, URL, title, HTTP status, selected
text, cookie *names* and redacted console errors.  Cookie values and typed credentials are
never written to the result document.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

ADAPTER_ID = "playwright"
NAME = "Playwright"
REQUIRES = ("node", "npx")
DESTINATION_POLICY = "target"
LICENSE_NOTICE = (
    "Playwright is Apache-2.0 licensed (github.com/microsoft/playwright). sak ships only its "
    "own runner; the npm package and the browser binaries are installed by the operator and "
    "are never vendored, committed or redistributed."
)
INSTALL_HINTS = (
    "npm install --global playwright",
    "npx playwright install chromium",
)
DEFAULT_BROWSER = "chromium"
BROWSER_SEARCH_ENV = "SAK_PLAYWRIGHT_BROWSERS_PATH"
RUNNER_RELPATH = Path("playwright") / "runner.mjs"
RESULT_RELPATH = Path("logs") / "playwright-result.json"
SCENARIO_ACTIONS = (
    "goto",
    "fill",
    "click",
    "select",
    "expect_url",
    "expect_text",
    "expect_status",
    "wait_for",
    "screenshot",
    "save_storage_state",
)
# Actions that can cause at least one network exchange; used for the budget estimate only.
NETWORK_ACTIONS = ("goto", "fill", "click", "select", "wait_for")
_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# build() records the resolved scenario on the step so estimate_requests() can count it after
# the run directory is known.  The key is private, never serialized and never a finding field.
_RESOLVED_KEY = "_playwright_scenario"
DEFAULT_OPTIONS: dict[str, Any] = {
    "scenario": None,
    "timeout_seconds": 60,
    "browser": DEFAULT_BROWSER,
    "headed": False,
}


def _options(step: dict[str, Any]) -> dict[str, Any]:
    merged = dict(DEFAULT_OPTIONS)
    for key, value in (step.get("options") or {}).items():
        if key in merged:
            merged[key] = value
    return merged


def _positive_int(value: Any, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"playwright option {name} must be an integer") from exc
    if number < 1:
        raise ValueError(f"playwright option {name} must be at least 1")
    return number


def runner_path() -> Path:
    return Path(__file__).resolve().parent / RUNNER_RELPATH


def _node(binary: str | None = None) -> str | None:
    return binary or shutil.which("node")


def _npx() -> str | None:
    return shutil.which("npx")


def _version(node: str) -> str | None:
    try:
        completed = subprocess.run(
            [node, "--version"], capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0].strip() if text else None


def browsers_dirs() -> list[Path]:
    """Candidate Playwright browser caches, in the order the runner would find them."""
    override = os.environ.get(BROWSER_SEARCH_ENV)
    if override:
        return [Path(override).expanduser()]
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if configured and configured != "0":
        return [Path(configured).expanduser()]
    candidates = [
        Path.home() / "Library" / "Caches" / "ms-playwright",
        Path.home() / ".cache" / "ms-playwright",
    ]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(Path(local) / "ms-playwright")
    return candidates


def browser_dir() -> Path | None:
    """Directory that holds a Chromium build, or ``None`` when none is visible."""
    for directory in browsers_dirs():
        try:
            if not directory.is_dir():
                continue
            if any(child.name.startswith(DEFAULT_BROWSER) for child in directory.iterdir()):
                return directory
        except OSError:
            continue
    return None


def browser_available() -> bool:
    return browser_dir() is not None


_MODULE_PROBE = "import('playwright').then(() => process.exit(0)).catch(() => process.exit(1))"


def module_available(node: str | None = None) -> bool:
    """Probe whether the runner's directory can import the playwright package."""
    if node is None:
        return False
    try:
        completed = subprocess.run(
            [node, "-e", _MODULE_PROBE],
            cwd=str(runner_path().parent),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def check() -> dict[str, Any]:
    """Report Node, npx, the runner, the playwright module and a cached Chromium build."""
    node = _node()
    npx = _npx()
    runner = runner_path()
    module = module_available(node)
    installed = browser_dir()
    missing: list[str] = []
    if node is None:
        missing.append("node")
    if npx is None:
        missing.append("npx")
    if not module:
        missing.append("playwright module")
    if not runner.is_file():
        missing.append("playwright runner")
    if installed is None:
        missing.append(f"{DEFAULT_BROWSER} browser")
    notes = [
        "check() only inspects the host; it never installs a package, downloads a browser or opens a page",
        "a dry run reads the scenario file and prints the command; only --execute starts Node",
        "the runner stays on the plan target's origin and records cookie names, never cookie values",
        "the package probe imports 'playwright' from the runner's directory; a global install needs NODE_PATH",
    ]
    if installed is None:
        notes.append(
            "no cached Chromium found; the operator runs `npx playwright install chromium` before --execute"
        )
    return {
        "adapter": ADAPTER_ID,
        "available": not missing,
        "binary": node,
        "npx": npx,
        "version": _version(node) if node else None,
        "runner": str(runner),
        "runner_found": runner.is_file(),
        "module_found": module,
        "browser": DEFAULT_BROWSER,
        "browser_found": installed is not None,
        "browser_path": str(installed) if installed is not None else None,
        "missing": missing,
        "hints": list(INSTALL_HINTS) if missing else [],
        "notes": notes,
        "license_notice": LICENSE_NOTICE,
    }


def scenario_path(step: dict[str, Any], run_dir: str | Path | None = None) -> Path:
    """Resolve ``options.scenario`` against the run directory and require a real file."""
    raw = _options(step).get("scenario")
    if not raw:
        raise ValueError("playwright needs options.scenario: the path to a scenario JSON file")
    path = Path(str(raw)).expanduser()
    if not path.is_absolute() and run_dir is not None:
        path = Path(run_dir).expanduser() / path
    if not path.is_file():
        raise ValueError(f"playwright scenario not found: {path}")
    return path.resolve()


def _step_error(index: int, message: str) -> ValueError:
    return ValueError(f"playwright scenario step {index}: {message}")


def load_scenario(path: str | Path) -> dict[str, Any]:
    """Read and validate a scenario file.  Unknown actions fail before a browser starts."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read playwright scenario {path}: {exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid playwright scenario JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"playwright scenario {path} must contain a JSON object")
    steps = payload.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"playwright scenario {path} needs a non-empty steps list")
    for index, item in enumerate(steps, start=1):
        if not isinstance(item, dict):
            raise _step_error(index, "must be a JSON object")
        action = str(item.get("action") or "")
        if action not in SCENARIO_ACTIONS:
            raise _step_error(
                index, f"unknown action {action!r}; choose from {', '.join(SCENARIO_ACTIONS)}"
            )
        if action == "goto" and not item.get("url"):
            raise _step_error(index, "goto needs a url")
        if action == "expect_url" and not (
            item.get("url") or item.get("contains") or item.get("pattern")
        ):
            raise _step_error(index, "expect_url needs url, contains or pattern")
        if action in {"fill", "click", "select"} and not item.get("selector"):
            raise _step_error(index, f"{action} needs a selector")
        if action == "fill" and "value" not in item:
            raise _step_error(index, "fill needs a value")
        if action == "expect_text" and not (item.get("text") or item.get("pattern")):
            raise _step_error(index, "expect_text needs text or pattern")
        if action == "expect_status" and not (
            item.get("status") is not None or item.get("equals") is not None
        ):
            raise _step_error(index, "expect_status needs status or equals")
        if action == "wait_for" and not (
            item.get("selector") or item.get("text") or item.get("timeout_ms")
        ):
            raise _step_error(index, "wait_for needs a selector, text or timeout_ms")
        if action == "save_storage_state" and not item.get("path"):
            raise _step_error(index, "save_storage_state needs a path")
    return payload


def _env_names(path: Path) -> list[str]:
    """Placeholder names referenced by a scenario.  Names only: values stay in the environment."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    seen: list[str] = []
    for name in _ENV_PLACEHOLDER.findall(text):
        if name not in seen:
            seen.append(name)
    return seen


def _scenario_actions(step: dict[str, Any]) -> list[str] | None:
    """Best-effort scenario read for the request estimate."""
    raw = step.get(_RESOLVED_KEY) or _options(step).get("scenario")
    if not raw:
        return None
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        scenario = load_scenario(path)
    except ValueError:
        return None
    return [str(item.get("action")) for item in scenario["steps"] if isinstance(item, dict)]


def estimate_requests(step: dict[str, Any], seconds: int = 60) -> int:
    """Worst-case request estimate: the initial page load plus one exchange per action.

    Only actions that can cause traffic are counted.  A scenario the adapter cannot read
    from the current directory is treated as a single request; the exact bound is enforced
    by the run's wall-clock timeout, not by the browser.
    """
    if seconds <= 0:
        return 0
    actions = _scenario_actions(step)
    if actions is None:
        return 1
    return 1 + sum(1 for action in actions if action in NETWORK_ACTIONS)


def build(
    step: dict[str, Any],
    target: str,
    *,
    run_dir: str | Path | None = None,
    binary: str | None = None,
) -> dict[str, Any]:
    """Build the dry-run command; nothing is executed and no browser is launched."""
    options = _options(step)
    node = _node(binary) or "node"
    runner = runner_path()
    scenario = scenario_path(step, run_dir)
    load_scenario(scenario)
    step[_RESOLVED_KEY] = str(scenario)
    timeout_seconds = _positive_int(options["timeout_seconds"], "timeout_seconds")
    browser = str(options["browser"] or DEFAULT_BROWSER)
    if run_dir is not None:
        output_path: str = str(Path(run_dir).expanduser() / RESULT_RELPATH)
        artifacts_dir = str(Path(run_dir).expanduser() / "artifacts" / "playwright")
    else:
        output_path = f"<run_dir>/{RESULT_RELPATH.as_posix()}"
        artifacts_dir = "<run_dir>/artifacts/playwright"
    command = [
        node,
        str(runner),
        "--scenario",
        str(scenario),
        "--target",
        target,
        "--out",
        output_path,
        "--artifacts-dir",
        artifacts_dir,
        "--timeout-seconds",
        str(timeout_seconds),
        "--browser",
        browser,
    ]
    if options.get("headed"):
        command.append("--headed")
    names = _env_names(scenario)
    notes = [
        "a dry run only reads the scenario; Node and the browser start on --execute",
        "the runner refuses navigation outside the plan target's origin and has no proxy or download step",
        "the result document records cookie names and metadata, never cookie values",
    ]
    if names:
        notes.append(
            "scenario reads these variables from the environment at execute time: " + ", ".join(names)
        )
    if options.get("headed"):
        notes.append("headed mode is enabled by the step; the default run is headless")
    return {
        "command": command,
        "display": " ".join(command),
        "notes": notes,
        "requires_scope": True,
        "output_path": output_path if run_dir is not None else None,
        "scenario": str(scenario),
        "env_names": names,
        "license_notice": LICENSE_NOTICE,
    }


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", str(value or "unknown").lower()).strip("-") or "unknown"


def _payload(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid playwright runner JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("playwright runner result must be a JSON object")
    steps = payload.get("steps")
    if not isinstance(steps, list):
        raise ValueError("playwright runner result needs a steps list")
    return payload


def parse(text: str) -> list[dict[str, Any]]:
    """Normalize the runner's candidate observations into ``needs_validation`` records.

    A failed expectation, an HTTP error response and a console error become one candidate
    each.  Cookies and storage state never become findings: they are evidence an operator
    attaches after review.
    """
    payload = _payload(text)
    if payload.get("error") and not payload["steps"]:
        raise ValueError(f"playwright runner error: {payload['error']}")
    fallback_target = str(payload.get("target") or "")
    observations = payload.get("observations")
    if observations is None:
        observations = []
    if not isinstance(observations, list):
        raise ValueError("playwright runner observations must be a list")
    findings: list[dict[str, Any]] = []
    for index, observation in enumerate(observations, start=1):
        if not isinstance(observation, dict):
            raise ValueError(f"playwright observation {index} must be a JSON object")
        kind = str(observation.get("kind") or "observation")
        title = str(observation.get("title") or kind.replace("_", " ")).strip()
        target = str(observation.get("url") or fallback_target)
        evidence = {
            "kind": kind,
            "step": observation.get("step"),
            "action": observation.get("action"),
            "detail": observation.get("detail"),
            "expected": observation.get("expected"),
            "observed": observation.get("observed"),
            "screenshot": observation.get("screenshot"),
        }
        findings.append(
            {
                "id": f"playwright:{index}:{_slug(kind)}:{_slug(title)[:60]}",
                "title": title or f"Playwright {kind}",
                "severity": str(observation.get("severity") or "medium").lower(),
                "status": "needs_validation",
                "source": "playwright",
                "target": target,
                "evidence": {
                    key: value for key, value in evidence.items() if value not in (None, "", [], {})
                },
            }
        )
    return findings


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _refused(reason: str) -> dict[str, Any]:
    return {
        "adapter": ADAPTER_ID,
        "refused": True,
        "reason": reason,
        "hints": list(INSTALL_HINTS),
        "license_notice": LICENSE_NOTICE,
        "findings": [],
    }


def execute(
    step: dict[str, Any],
    target: str,
    *,
    binary: str | None = None,
    timeout: int = 300,
    run_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Run the scenario once through the Node runner.  Callers gate scope and budget first."""
    node = _node(binary)
    if node is None:
        return _refused("node is not installed; the Playwright runner needs Node.js")
    if _npx() is None:
        return _refused("npx is not installed; it is the documented Playwright install path")
    if not module_available(node):
        return _refused(
            "the playwright module is not importable from the runner's directory; install it "
            "there or set NODE_PATH"
        )
    runner = runner_path()
    if not runner.is_file():
        return _refused(f"playwright runner not found at {runner}")
    if not browser_available():
        return _refused(
            f"no cached {DEFAULT_BROWSER} browser found; run `npx playwright install {DEFAULT_BROWSER}`"
        )

    if run_dir is None:
        with tempfile.TemporaryDirectory(prefix="sak-playwright-") as temporary:
            result = _run(step, target, node=node, timeout=timeout, run_dir=Path(temporary))
        result["output_path"] = None
        return result
    return _run(step, target, node=node, timeout=timeout, run_dir=Path(run_dir))


def _run(
    step: dict[str, Any], target: str, *, node: str, timeout: int, run_dir: Path
) -> dict[str, Any]:
    plan = build(step, target, run_dir=run_dir, binary=node)
    output_path = plan["output_path"]
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            plan["command"], capture_output=True, text=True, timeout=timeout, check=False
        )
        returncode: int | None = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout, stderr = _text(exc.stdout), _text(exc.stderr)
    duration = round(time.monotonic() - started, 3)

    raw = ""
    if output_path and Path(output_path).is_file():
        raw = Path(output_path).read_text(encoding="utf-8", errors="replace")
    result: dict[str, Any] = {
        "adapter": ADAPTER_ID,
        "command": plan["command"],
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": duration,
        "stdout": stdout,
        "stderr": stderr,
        "output_path": output_path,
        "findings": [],
        "notes": plan["notes"],
        "license_notice": LICENSE_NOTICE,
    }
    if not raw.strip():
        result["parse_error"] = (
            "the Playwright runner did not write a result document"
            + (f" (exit {returncode})" if returncode is not None else "")
        )
        return result
    try:
        result["findings"] = parse(raw)
    except ValueError as exc:
        result["parse_error"] = str(exc)
    return result
