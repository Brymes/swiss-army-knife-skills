// Playwright smoke checks for the vuln-bank harness.
//
// These are readiness and evidence checks only: they show what a browser actually sees.
// Run through targets/vuln-bank/run.sh, which sets BASE_URL to the authorized origin.
// Browsers are installed by the operator (`npx playwright install chromium`), never
// committed. No credentials, writes, brute force or destructive actions live here.
const { test, expect } = require('@playwright/test');

const BASE_URL = (process.env.BASE_URL || 'http://127.0.0.1:5000').replace(/\/$/, '');

test.describe('vuln-bank smoke', () => {
  test('healthz reports a ready database', async ({ request }) => {
    const response = await request.get(`${BASE_URL}/healthz`);
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.status).toBe('ok');
    expect(body.database).toBe('up');
  });

  test('login page renders a form for the authenticated flows', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/login`);
    expect(response === null || response.status() < 500).toBeTruthy();
    await expect(page.locator('form').first()).toBeVisible();
    const storage = await page.evaluate(() => Object.keys(window.localStorage));
    expect(Array.isArray(storage)).toBe(true);
  });
});
