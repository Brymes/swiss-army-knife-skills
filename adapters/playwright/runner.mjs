#!/usr/bin/env node
/**
 * sak Playwright runner.
 *
 * Usage:
 *   node runner.mjs --scenario file.json --target http://host:port \
 *     --out result.json [--artifacts-dir DIR] [--timeout-seconds 60] \
 *     [--browser chromium] [--headed]
 *   node runner.mjs --scenario file.json --check
 *
 * The runner opens the plan target once, then executes the scenario's listed actions in
 * order.  Every navigation must stay on the target's origin.  It writes a JSON result
 * document (mode 0600) with per-step status, URL, title, HTTP status, selected text,
 * cookie metadata (names and flags only, never values), redacted console errors and
 * candidate observations.
 *
 * `--check` validates a scenario and reports the environment variable names it needs; it
 * does not import Playwright, launch a browser or touch the network.
 *
 * Exit codes: 0 ok, 1 a step failed, 2 usage/scenario error, 3 playwright module missing,
 * 4 timeout.
 */

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';

const ACTIONS = new Set([
  'goto',
  'fill',
  'click',
  'select',
  'expect_url',
  'expect_text',
  'expect_status',
  'wait_for',
  'screenshot',
  'save_storage_state',
]);
const ENV_PATTERN = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
const SECRETS = new Set();
const MAX_TEXT = 2000;

class UsageError extends Error {}
class ExpectationError extends Error {
  constructor(message, expected, observed) {
    super(message);
    this.expected = expected;
    this.observed = observed;
  }
}
class ModuleMissing extends Error {}

// --------------------------------------------------------------------------- arguments

function parseArgs(argv) {
  const args = {
    scenario: null,
    target: null,
    out: null,
    artifactsDir: null,
    timeoutSeconds: 60,
    browser: 'chromium',
    headed: false,
    check: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const value = () => {
      index += 1;
      if (index >= argv.length) throw new UsageError(`missing value for ${token}`);
      return argv[index];
    };
    switch (token) {
      case '--scenario':
        args.scenario = value();
        break;
      case '--target':
        args.target = value();
        break;
      case '--out':
        args.out = value();
        break;
      case '--artifacts-dir':
        args.artifactsDir = value();
        break;
      case '--timeout-seconds':
        args.timeoutSeconds = Number(value());
        break;
      case '--browser':
        args.browser = value();
        break;
      case '--headed':
        args.headed = true;
        break;
      case '--check':
        args.check = true;
        break;
      default:
        throw new UsageError(`unknown argument ${token}`);
    }
  }
  if (!args.scenario) throw new UsageError('--scenario is required');
  if (!Number.isFinite(args.timeoutSeconds) || args.timeoutSeconds <= 0) {
    throw new UsageError('--timeout-seconds must be a positive number');
  }
  if (!args.check && (!args.target || !args.out)) {
    throw new UsageError('--target and --out are required unless --check is passed');
  }
  return args;
}

// --------------------------------------------------------------------------- scenario

function readScenario(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new UsageError(`cannot read scenario ${path}: ${error.message}`);
  }
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (error) {
    throw new UsageError(`invalid scenario JSON in ${path}: ${error.message}`);
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new UsageError(`scenario ${path} must contain a JSON object`);
  }
  if (!Array.isArray(payload.steps) || payload.steps.length === 0) {
    throw new UsageError(`scenario ${path} needs a non-empty steps list`);
  }
  payload.steps.forEach((step, offset) => {
    const index = offset + 1;
    if (!step || typeof step !== 'object' || Array.isArray(step)) {
      throw new UsageError(`scenario step ${index} must be a JSON object`);
    }
    if (!ACTIONS.has(step.action)) {
      throw new UsageError(`scenario step ${index} has unknown action ${JSON.stringify(step.action)}`);
    }
    if (step.action === 'goto' && !step.url) {
      throw new UsageError(`scenario step ${index} (goto) needs a url`);
    }
    if (step.action === 'expect_url' && !step.url && !step.contains && !step.pattern) {
      throw new UsageError(`scenario step ${index} (expect_url) needs url, contains or pattern`);
    }
    if (['fill', 'click', 'select'].includes(step.action) && !step.selector) {
      throw new UsageError(`scenario step ${index} (${step.action}) needs a selector`);
    }
    if (step.action === 'fill' && step.value === undefined) {
      throw new UsageError(`scenario step ${index} (fill) needs a value`);
    }
    if (step.action === 'expect_text' && !step.text && !step.pattern) {
      throw new UsageError(`scenario step ${index} (expect_text) needs text or pattern`);
    }
    if (step.action === 'expect_status' && step.status === undefined && step.equals === undefined) {
      throw new UsageError(`scenario step ${index} (expect_status) needs status or equals`);
    }
    if (step.action === 'wait_for' && !step.selector && !step.text && !step.timeout_ms) {
      throw new UsageError(`scenario step ${index} (wait_for) needs a selector, text or timeout_ms`);
    }
    if (step.action === 'save_storage_state' && !step.path) {
      throw new UsageError(`scenario step ${index} (save_storage_state) needs a path`);
    }
  });
  return payload;
}

function collectEnvNames(value, names = new Set()) {
  if (typeof value === 'string') {
    for (const match of value.matchAll(ENV_PATTERN)) names.add(match[1]);
    return names;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectEnvNames(item, names));
    return names;
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (key === 'action') continue;
      collectEnvNames(item, names);
    }
  }
  return names;
}

function substituteString(value, env) {
  return value.replace(ENV_PATTERN, (_, name) => {
    if (!(name in env) || env[name] === '') {
      throw new UsageError(`scenario needs environment variable ${name}, which is not set`);
    }
    SECRETS.add(env[name]);
    return env[name];
  });
}

function substitute(value, env) {
  if (typeof value === 'string') return substituteString(value, env);
  if (Array.isArray(value)) return value.map((item) => substitute(item, env));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = key === 'action' ? item : substitute(item, env);
    }
    return out;
  }
  return value;
}

// --------------------------------------------------------------------------- redaction

function redact(text) {
  if (typeof text !== 'string') return text;
  let result = text;
  for (const secret of [...SECRETS].sort((a, b) => b.length - a.length)) {
    if (!secret) continue;
    result = result.split(secret).join('***');
  }
  return result;
}

function redactDeep(value) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(redactDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = redactDeep(item);
    return out;
  }
  return value;
}

// --------------------------------------------------------------------------- helpers

function isHttpUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function absoluteUrl(value, base, origin) {
  let url;
  try {
    url = new URL(value, base);
  } catch {
    throw new Error(`not a usable URL: ${value}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`unsupported URL scheme ${url.protocol}`);
  }
  if (url.origin !== origin) {
    throw new Error(`refusing to leave the authorized target origin ${origin} for ${url.origin}`);
  }
  return url.href;
}

function artifactsPath(args, value) {
  const base = args.artifactsDir || dirname(resolve(args.out));
  return isAbsolute(value) ? value : resolve(base, value);
}

function writeJson(path, payload, mode) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`, { encoding: 'utf8', mode });
  if (mode) chmodSync(path, mode);
}

function truncate(text) {
  const value = String(text ?? '');
  return value.length > MAX_TEXT ? `${value.slice(0, MAX_TEXT)}…` : value;
}

function safeTitle(page) {
  return page.title().catch(() => '');
}

// --------------------------------------------------------------------------- run

async function loadBrowser(name) {
  let module;
  try {
    module = await import('playwright');
  } catch (error) {
    throw new ModuleMissing(
      `the playwright module is not importable from this Node environment: ${error.message}`,
    );
  }
  const browserType = module[name];
  if (!browserType) throw new ModuleMissing(`playwright exposes no browser type ${name}`);
  return browserType;
}

async function runScenario(args, scenario, result, state) {
  const browserType = await loadBrowser(args.browser);
  const targetUrl = new URL(args.target);
  const origin = targetUrl.origin;
  const browser = await browserType.launch({ headless: !args.headed });
  state.browser = browser;
  result.browser = { name: args.browser, version: browser.version() };
  const context = await browser.newContext({
    viewport: scenario.viewport || { width: 1280, height: 800 },
    ignoreHTTPSErrors: Boolean(scenario.ignore_https_errors),
  });
  const page = await context.newPage();
  let stepIndex = 0;
  page.on('console', (message) => {
    if (message.type() === 'error') {
      result.console_errors.push({ step: stepIndex, type: 'console', text: truncate(message.text()) });
    }
  });
  page.on('pageerror', (error) => {
    result.console_errors.push({ step: stepIndex, type: 'pageerror', text: truncate(error.message) });
  });

  let lastStatus = null;
  const initial = await page.goto(args.target, { waitUntil: 'load' });
  lastStatus = initial ? initial.status() : null;
  result.initial = {
    url: page.url(),
    title: await safeTitle(page),
    status: lastStatus,
  };

  for (const [offset, rawStep] of scenario.steps.entries()) {
    stepIndex = offset + 1;
    const step = substitute(rawStep, process.env);
    const record = {
      index: stepIndex,
      action: step.action,
      status: 'failed',
      url: page.url(),
      title: await safeTitle(page),
      status_code: lastStatus,
      selected_text: null,
      detail: null,
      error: null,
      screenshot: null,
    };
    try {
      switch (step.action) {
        case 'goto': {
          const url = absoluteUrl(step.url, page.url(), origin);
          const response = await page.goto(url, {
            waitUntil: step.wait_until || 'load',
            timeout: step.timeout_ms || undefined,
          });
          lastStatus = response ? response.status() : null;
          record.detail = `navigated to ${url}`;
          if (lastStatus !== null && lastStatus >= 400) {
            result.observations.push({
              kind: 'http_error',
              severity: 'low',
              title: `HTTP ${lastStatus} after goto`,
              step: stepIndex,
              action: step.action,
              url: page.url(),
              detail: `the target answered ${lastStatus}`,
              observed: lastStatus,
            });
          }
          break;
        }
        case 'fill':
          await page.fill(step.selector, String(step.value), { timeout: step.timeout_ms || undefined });
          record.detail = 'filled a field; the value is not recorded';
          break;
        case 'click':
          await page.click(step.selector, { timeout: step.timeout_ms || undefined });
          break;
        case 'select':
          await page.selectOption(step.selector, String(step.value), {
            timeout: step.timeout_ms || undefined,
          });
          break;
        case 'expect_url': {
          const observed = page.url();
          const expected = step.url ? absoluteUrl(step.url, observed, origin) : null;
          const matched = step.pattern
            ? new RegExp(step.pattern).test(observed)
            : step.contains
              ? observed.includes(step.contains)
              : observed === expected;
          record.selected_text = observed;
          if (!matched) {
            throw new ExpectationError(
              `url did not match the expectation (expected ${expected || step.contains || step.pattern}, observed ${observed})`,
              expected || step.contains || step.pattern,
              observed,
            );
          }
          break;
        }
        case 'expect_text': {
          const selector = step.selector || 'body';
          const text = truncate(await page.locator(selector).first().innerText());
          record.selected_text = text;
          const matched = step.pattern
            ? new RegExp(step.pattern).test(text)
            : text.includes(String(step.text));
          if (!matched) {
            throw new ExpectationError(
              `text ${JSON.stringify(step.text || step.pattern)} was not found in ${selector}`,
              step.text || step.pattern,
              text.slice(0, 500),
            );
          }
          break;
        }
        case 'expect_status': {
          const expected = Number(step.status !== undefined ? step.status : step.equals);
          record.selected_text = lastStatus === null ? null : String(lastStatus);
          if (lastStatus !== expected) {
            throw new ExpectationError(
              `status code mismatch (expected ${expected}, observed ${lastStatus})`,
              expected,
              lastStatus,
            );
          }
          break;
        }
        case 'wait_for': {
          if (step.selector) {
            await page.waitForSelector(step.selector, { timeout: step.timeout_ms || undefined });
          } else if (step.text) {
            await page.getByText(step.text, { exact: Boolean(step.exact) }).first().waitFor({
              timeout: step.timeout_ms || undefined,
            });
          } else {
            await page.waitForTimeout(step.timeout_ms || 250);
          }
          break;
        }
        case 'screenshot': {
          const path = artifactsPath(args, step.path || `step-${stepIndex}.png`);
          mkdirSync(dirname(path), { recursive: true });
          await page.screenshot({ path, fullPage: step.full_page !== false });
          record.screenshot = path;
          break;
        }
        case 'save_storage_state': {
          const path = artifactsPath(args, step.path);
          mkdirSync(dirname(path), { recursive: true });
          await context.storageState({ path });
          chmodSync(path, 0o600);
          result.storage_state = path;
          record.detail = `storage state written to ${path}; it holds cookie values and must never be committed`;
          break;
        }
        default:
          throw new Error(`unknown action ${step.action}`);
      }
      record.status = 'passed';
    } catch (error) {
      record.error = error.message;
      if (error instanceof ExpectationError) {
        result.observations.push({
          kind: 'expectation_failed',
          severity: 'medium',
          title: `Expectation failed: ${step.action}`,
          step: stepIndex,
          action: step.action,
          url: page.url(),
          detail: error.message,
          expected: error.expected,
          observed: error.observed,
          screenshot: record.screenshot,
        });
      }
    }
    record.url = page.url();
    record.title = await safeTitle(page);
    record.status_code = lastStatus;
    result.steps.push(record);
  }

  const cookies = await context.cookies();
  result.cookies = cookies.map((cookie) => ({
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
    http_only: Boolean(cookie.httpOnly),
    secure: Boolean(cookie.secure),
    same_site: cookie.sameSite,
    expires: cookie.expires,
  }));
  if (result.cookies.length) {
    result.notes.push('cookie names and flags only; cookie values are never written to this document');
  }
  await context.close();
  await browser.close();
  state.browser = null;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const scenario = readScenario(args.scenario);
  const envNames = [...collectEnvNames(scenario.steps)];
  const startedAt = new Date().toISOString();
  const result = {
    schema_version: '1',
    runner: 'sak-playwright-runner',
    scenario: resolve(args.scenario),
    target: args.target ? redact(args.target) : null,
    started_at: startedAt,
    finished_at: null,
    timed_out: false,
    ok: false,
    error: null,
    initial: null,
    browser: null,
    steps: [],
    cookies: [],
    console_errors: [],
    observations: [],
    env_names: envNames,
    storage_state: null,
    notes: [],
  };

  if (args.check) {
    const missing = envNames.filter((name) => !(name in process.env) || process.env[name] === '');
    const summary = {
      ok: missing.length === 0,
      scenario: result.scenario,
      steps: scenario.steps.length,
      env_names: envNames,
      missing_env: missing,
      browser: args.browser,
    };
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    return missing.length === 0 ? 0 : 2;
  }

  if (!isHttpUrl(args.target)) {
    result.error = 'target must be an absolute http(s) URL';
    result.finished_at = new Date().toISOString();
    writeJson(args.out, redactDeep(result), 0o600);
    return 2;
  }

  const timeoutMs = args.timeoutSeconds * 1000;
  const state = { browser: null };
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(`runner exceeded ${args.timeoutSeconds}s`);
      error.timedOut = true;
      reject(error);
    }, timeoutMs);
  });
  try {
    await Promise.race([runScenario(args, scenario, result, state), timeout]);
    result.ok = result.steps.every((step) => step.status === 'passed');
  } catch (error) {
    result.error = error.message;
    result.timed_out = Boolean(error.timedOut);
  } finally {
    clearTimeout(timer);
    if (state.browser) {
      await Promise.race([
        state.browser.close().catch(() => {}),
        new Promise((resolveClose) => setTimeout(resolveClose, 5000)),
      ]);
      state.browser = null;
    }
  }
  result.finished_at = new Date().toISOString();
  if (result.error && !result.timed_out) {
    result.ok = false;
  }
  writeJson(args.out, redactDeep(result), 0o600);
  process.stdout.write(
    `${JSON.stringify({
      ok: result.ok,
      steps: result.steps.length,
      failed: result.steps.filter((step) => step.status !== 'passed').length,
      observations: result.observations.length,
      out: args.out,
    })}\n`,
  );
  if (result.timed_out) return 4;
  if (result.error && result.error.startsWith('the playwright module')) return 3;
  if (result.error) return 2;
  return result.ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    const payload = {
      ok: false,
      error: error.message,
      kind: error instanceof UsageError ? 'usage' : error instanceof ModuleMissing ? 'module' : 'runner',
    };
    process.stderr.write(`${JSON.stringify(payload)}\n`);
    process.exit(error instanceof UsageError ? 2 : 3);
  },
);
