# Third-party notices

This project is MIT licensed (see `LICENSE`). It vendors two MIT-licensed agent
skills. Both are included unmodified; the full license text of each is kept with
the vendored files.

Machine-readable pins and file checksums: [`vendor/sources.lock.json`](vendor/sources.lock.json).
Copy details and the integration contract: [`vendor/PROVENANCE.md`](vendor/PROVENANCE.md).

---

## 1. PWN HUNTER (`pwn-hunter`)

- Upstream: <https://github.com/BountyForge-xyz/pwn-skill>
- Default branch: `main`
- Pinned commit: `403310598eab3c99c24082795c35b76e790ed6a5` (2026-11-06)
- Local path: `vendor/skills/pwn-hunter/`
- License: MIT — full text in `vendor/skills/pwn-hunter/LICENSE`

```text
MIT License

Copyright (c) 2026 BountyForge-xyz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. security-audit (`security-audit`)

- Upstream: <https://github.com/cloudflare/security-audit-skill>
- Default branch: `main`
- Pinned commit: `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (2026-09-14)
- Local path: `vendor/skills/security-audit/`
- License: MIT — full text in `vendor/skills/security-audit/LICENSE`

```text
MIT License

Copyright (c) 2025-2026 Cloudflare, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Not vendored

Heavy engines and tools under other licenses (T3MP3ST, PentAGI, ARTEX,
Blackbird, AppleResearch and similar) stay external, gitignored under
`vendor/external/`, and are never copied into this repository. No GPL, AGPL or
unlicensed code is vendored here.
