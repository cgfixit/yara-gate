// Check in headless Chromium that each shape doc_svg_active_link reads is active, and that
// the no-op target it exempts is not.
//
// Each fixture is an inert SVG or HTML page of this file's own, served from a routed origin.
// Its script only sets window.__ran; a probe.test URL it requests is answered locally; every
// other request is recorded and aborted, so nothing leaves the machine. A row "ran" when the
// fixture's script set the flag after a click on its link, and "loaded" when the page
// requested a probe.test URL (a frame, an object, an embed, a form submit, or a refresh).
//
//     NODE_PATH=$(npm root -g) node docs/research/svg_active_oracle.js
//
// Not run by CI: it needs Node, Playwright, and a Chromium build. The scanner's verdicts on the
// same shapes are pairs in docs/verification/check_rule_pairs.py and cases in
// docs/research/probe_detection_gaps.py. See
// docs/verification/2026-11-10-svg-links-and-invisible-runs.md for what was measured.
const { chromium } = require('playwright');

const NS = 'xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"';
const XH = 'xmlns="http://www.w3.org/1999/xhtml"';
const RUN = 'window.__ran=1';
const svg = (body) => `<svg ${NS} width="300" height="200">${body}</svg>`;
const link = (attr, target) => svg(`<a ${attr}="${target}"><rect id="hit" width="300" height="200" fill="#ccc"/></a>`);
const page = (body) => `<!doctype html><html><body>${body}</body></html>`;

// [label, content type, body, action]: action is "click" (click the rect) or "wait".
const CASES = [
  ['a href javascript', 'svg', link('href', `javascript:${RUN}`), 'click'],
  ['a xlink:href javascript', 'svg', link('xlink:href', `javascript:${RUN}`), 'click'],
  ['a href javascript:void(0)', 'svg', link('href', 'javascript:void(0)'), 'click'],
  ['a href javascript:void(window.__ran=1)', 'svg', link('href', `javascript:void(${RUN})`), 'click'],
  ['set href to javascript', 'svg', svg(`<a><set attributeName="href" to="javascript:${RUN}"/><rect id="hit" width="300" height="200"/></a>`), 'click'],
  ['animate href values javascript', 'svg', svg(`<a><animate attributeName="href" values="javascript:${RUN}" dur="10s"/><rect id="hit" width="300" height="200"/></a>`), 'click'],
  ['foreignObject iframe', 'svg', svg(`<foreignObject width="300" height="200"><iframe ${XH} src="https://probe.test/frame"></iframe></foreignObject>`), 'wait'],
  ['foreignObject object', 'svg', svg(`<foreignObject width="300" height="200"><object ${XH} data="https://probe.test/object" type="text/html"></object></foreignObject>`), 'wait'],
  ['foreignObject embed', 'svg', svg(`<foreignObject width="300" height="200"><embed ${XH} src="https://probe.test/embed" type="text/html"/></foreignObject>`), 'wait'],
  ['foreignObject form submit', 'svg', svg(`<foreignObject width="300" height="200"><form ${XH} action="https://probe.test/form" method="get"><input name="u" value="x"/><button id="hit" type="submit">go</button></form></foreignObject>`), 'click'],
  ['foreignObject meta refresh', 'svg', svg(`<foreignObject width="300" height="200"><meta ${XH} http-equiv="refresh" content="0;url=https://probe.test/refresh"/></foreignObject>`), 'wait'],
  ['inline svg in html: a href javascript', 'html', page(link('href', `javascript:${RUN}`)), 'click'],
  ['inline svg in html: fo iframe', 'html', page(svg('<foreignObject width="300" height="200"><iframe src="https://probe.test/frame"></iframe></foreignObject>')), 'wait'],
  ['inline svg in html: fo meta refresh', 'html', page(svg('<foreignObject width="300" height="200"><meta http-equiv="refresh" content="0;url=https://probe.test/refresh"></foreignObject>')), 'wait'],
  ['foreignObject div label (benign)', 'svg', svg(`<foreignObject width="300" height="200"><div ${XH}><span>Start</span></div></foreignObject>`), 'wait'],
];

(async () => {
  const browser = await chromium.launch();
  for (const [label, kind, body, action] of CASES) {
    const context = await browser.newContext();
    const tab = await context.newPage();
    const probed = [];
    const other = [];
    await context.route('**/*', (route) => {
      const url = route.request().url();
      if (url === 'https://fixture.test/doc') {
        return route.fulfill({ status: 200, contentType: kind === 'svg' ? 'image/svg+xml' : 'text/html', body });
      }
      if (url.startsWith('https://probe.test/')) {
        probed.push(url.replace(/\?.*/, ''));
        return route.fulfill({ status: 200, contentType: 'text/html', body: '<p>probe</p>' });
      }
      other.push(url);
      return route.abort();
    });
    let note = '';
    try {
      await tab.goto('https://fixture.test/doc', { waitUntil: 'load', timeout: 5000 });
      if (action === 'click') {
        await tab.click('#hit', { timeout: 2000 }).catch((e) => { note = `click failed: ${e.message.split('\n')[0]}`; });
      }
      await tab.waitForTimeout(1500);
    } catch (e) {
      note = `nav: ${e.message.split('\n')[0]}`;
    }
    let ran = false;
    try { ran = await tab.evaluate(() => window.__ran === 1); } catch (e) { note += ` eval: ${e.message.split('\n')[0]}`; }
    const loaded = [...new Set(probed)].join(',');
    console.log(`${label.padEnd(44)} ran=${ran ? 'yes' : 'no '} loaded=${loaded || '-'} final=${tab.url()}${other.length ? ' aborted=' + other.length : ''}${note ? ' ' + note : ''}`);
    await context.close();
  }
  await browser.close();
})();
