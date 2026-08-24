#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium, firefox, webkit } = require('playwright');

const baseURL = (process.env.STCONTROL_BROWSER_BASE_URL || '').replace(/\/$/, '');
const outputDir = process.env.STCONTROL_BROWSER_OUTPUT_DIR || '';
const ignoreHTTPSErrors = process.env.STCONTROL_BROWSER_IGNORE_HTTPS_ERRORS === '1';
const settleMilliseconds = Number(process.env.STCONTROL_BROWSER_SETTLE_MS || 750);
if (!/^https:\/\//.test(baseURL) || !outputDir) {
  console.error('set STCONTROL_BROWSER_BASE_URL=https://... and STCONTROL_BROWSER_OUTPUT_DIR');
  process.exit(2);
}

fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });

const engines = { chromium, firefox, webkit };
const widths = [320, 375, 768, 1024, 1440];
const routes = ['/login', '/register', '/select-node', '/admin/login', '/account', '/conflict', '/'];
const results = [];
let failed = false;

(async () => {
  for (const [engineName, engine] of Object.entries(engines)) {
    const browser = await engine.launch({ headless: true });
    try {
      for (const width of widths) {
        const context = await browser.newContext({
          viewport: { width, height: 900 }, ignoreHTTPSErrors,
        });
        const page = await context.newPage();
        const errors = [];
        const expectedWarnings = [];
        page.on('pageerror', error => errors.push(`pageerror: ${error.message}`));
        page.on('console', message => {
          if (message.type() !== 'error') return;
          const text = `console: ${message.text()}`;
          // Anonymous pages intentionally probe the opaque session endpoint;
          // its 401 is handled by the application and is not an exception.
          if (text.includes('server responded with a status of 401')) {
            expectedWarnings.push(text);
          } else {
            errors.push(text);
          }
        });
        for (const route of routes) {
          let status = 0;
          let overflow = false;
          let title = '';
          try {
            const response = await page.goto(baseURL + route, {
              waitUntil: 'domcontentloaded', timeout: 30000,
            });
            status = response ? response.status() : 0;
            await page.waitForTimeout(settleMilliseconds);
            overflow = await page.evaluate(() =>
              document.documentElement.scrollWidth > window.innerWidth + 1,
            );
            title = await page.title();
          } catch (error) {
            errors.push(`navigation ${route}: ${error.message}`);
          }
          const routeFailed = status < 200 || status >= 400 || overflow;
          failed ||= routeFailed;
          results.push({ engine: engineName, width, route, status, overflow, title, routeFailed });
        }
        await page.goto(baseURL + '/login', { waitUntil: 'domcontentloaded', timeout: 30000 });
        await page.screenshot({
          path: path.join(outputDir, `${engineName}-${width}-login.png`), fullPage: true,
        });
        if (errors.length) {
          failed = true;
          results.push({ engine: engineName, width, errors });
        }
        if (expectedWarnings.length) {
          results.push({ engine: engineName, width, expectedWarnings });
        }
        await context.close();
      }
    } finally {
      await browser.close();
    }
  }
  fs.writeFileSync(
    path.join(outputDir, 'browser-matrix-results.json'),
    JSON.stringify(results, null, 2) + '\n',
    { mode: 0o600 },
  );
  const routeChecks = results.filter(result => Object.hasOwn(result, 'route'));
  const errorGroups = results.filter(result => Object.hasOwn(result, 'errors'));
  console.log(`browser_matrix route_checks=${routeChecks.length} error_groups=${errorGroups.length} result=${failed ? 'FAIL' : 'PASS'}`);
  process.exitCode = failed ? 1 : 0;
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
