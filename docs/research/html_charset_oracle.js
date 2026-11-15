// Ask headless Chromium which encoding it decodes each document with.
//
//   node docs/research/html_charset_oracle.js DIR
//
// DIR holds the documents and the manifest.json that probe_html_charset_browser.py writes:
// [{file}]. Each document is loaded from a file:// URL, so its type comes from its name, as
// for a saved page, and DIR/chromium.json gets {file: document.characterSet}.
//
// Every request other than the document itself is aborted and scripting is off, so nothing a
// document names is fetched or run. Needs Node and Playwright with a Chromium build. Not run
// by CI.
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const dir = path.resolve(process.argv[2]);
  const cases = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const browser = await chromium.launch();
  const context = await browser.newContext({ javaScriptEnabled: false });
  await context.route('**/*', (route) => {
    const url = route.request().url();
    return url.startsWith('file://') && url.startsWith('file://' + dir) ? route.continue() : route.abort();
  });
  const page = await context.newPage();
  const out = {};
  for (const c of cases) {
    await page.goto('file://' + path.join(dir, c.file), { waitUntil: 'load' });
    out[c.file] = await page.evaluate(() => document.characterSet);
  }
  out['(browser)'] = browser.version();
  await browser.close();
  fs.writeFileSync(path.join(dir, 'chromium.json'), JSON.stringify(out, null, 1));
})();
