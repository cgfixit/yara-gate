// Ask headless Chromium whether each marked text of each document is drawn.
//
//   ORACLE_JS=1 node docs/research/html_hidden_oracle.js cases.json drawn.json
//
// cases.json is written by probe_html_hidden_browser.py: [{id, html}], every text a
// "MARKn lorem ipsum". The result maps each id to {MARKn: verdict}. A verdict that starts
// with "shown" (or "title", the document's own title) means drawn; anything else names why
// it is not: display, visibility, opacity, tiny, clipped, offscreen, transparent,
// camouflage, no-box, absent.
//
// Every request is aborted, so nothing a document names is fetched. Scripting is on only
// with ORACLE_JS=1, which is what a person's browser does and what decides how a noscript
// body is parsed; leave it unset for documents made from files you did not write.
// Needs Node and Playwright with a Chromium build. Not run by CI.
const fs = require('fs');
const { chromium } = require('playwright');

function oracle() {
  const out = {};
  const parse = (value) => {
    const m = /rgba?\(([^)]+)\)/.exec(value);
    if (!m) return null;
    const p = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  };
  // True when an ancestor that clips its content leaves none of this rectangle inside its
  // box. An absolutely positioned box is clipped only by ancestors from its containing
  // block up.
  const clipped = (el, r) => {
    let needPositioned = false;
    for (let a = el; a && a.nodeType === 1; a = a.parentElement) {
      const s = getComputedStyle(a);
      // The old clip property: a rectangle of no area on a positioned box draws nothing.
      if ((s.position === 'absolute' || s.position === 'fixed') && s.clip && s.clip !== 'auto') {
        const c = /rect\(([^)]+)\)/.exec(s.clip);
        if (c) {
          const v = c[1].split(/[,\s]+/).filter(Boolean).map(parseFloat);
          if (v.length === 4 && (v[1] - v[3] <= 0 || v[2] - v[0] <= 0)) return true;
        }
      }
      const clips = s.overflowX !== 'visible' || s.overflowY !== 'visible';
      if (clips && (!needPositioned || s.position !== 'static')) {
        // Overflow clips at the padding box: a border around a zero-size box shows no text.
        const b = a.getBoundingClientRect();
        const left = b.left + a.clientLeft, top = b.top + a.clientTop;
        const right = left + a.clientWidth, bottom = top + a.clientHeight;
        const w = Math.min(r.right, right) - Math.max(r.left, left);
        const h = Math.min(r.bottom, bottom) - Math.max(r.top, top);
        // Less than six pixels of a glyph in either direction is not readable text.
        if (w < 6 || h < 6) return true;
      }
      if (needPositioned && s.position !== 'static') needPositioned = false;
      if (s.position === 'fixed') return false;
      if (s.position === 'absolute') needPositioned = true;
    }
    return false;
  };
  const judge = (el, range) => {
    if (!el) return 'absent';
    // The document's own title. An svg title is a tooltip and is judged like any element.
    const titled = el.closest('title');
    if (titled && titled.namespaceURI === 'http://www.w3.org/1999/xhtml') return 'title';
    if (el.closest('script,style,noscript,head')) return 'not-text';
    if (!el.checkVisibility()) return 'display';
    // hidden=until-found keeps the box and skips what is inside it.
    for (let a = el; a && a.nodeType === 1; a = a.parentElement) {
      if (getComputedStyle(a).contentVisibility === 'hidden') return 'display';
    }
    if (!el.checkVisibility({ visibilityProperty: true })) return 'visibility';
    if (!el.checkVisibility({ opacityProperty: true })) return 'opacity';
    const cs = getComputedStyle(el);
    const size = parseFloat(cs.fontSize);
    // Under three pixels a glyph is a speck: a 1pt size under a heading's 2em is 2.67px.
    if (size < 3) return 'tiny:' + size;
    // A textarea draws its text inside the control; the text node has no box of its own.
    const control = el.tagName === 'TEXTAREA';
    const rects = (control ? [el.getBoundingClientRect()] : Array.from(range.getClientRects()))
      .filter((r) => r.width > 0 && r.height > 0);
    if (!rects.length) return 'no-box';
    // A control squeezed to a sliver draws no readable text, whatever its border adds.
    if (control && (el.clientHeight < 8 || el.clientWidth < 8)) return 'clipped';
    const r = rects[0];
    // Left of or above the page cannot be scrolled to; right of or below it can.
    if (r.right <= 0 || r.bottom <= 0) return 'offscreen';
    if (clipped(control ? el.parentElement : el, r)) return 'clipped';
    const ink = parse(cs.color);
    if (ink && ink[3] < 0.03) return 'transparent';
    let backdrop = null;
    for (let a = el; a && a.nodeType === 1; a = a.parentElement) {
      const s = getComputedStyle(a);
      if (s.backgroundImage && s.backgroundImage !== 'none') return 'shown:image';
      const bg = parse(s.backgroundColor);
      if (bg && bg[3] > 0.03) { backdrop = bg; break; }
    }
    if (ink) {
      if (backdrop) {
        const d = Math.max(
          Math.abs(ink[0] - backdrop[0]), Math.abs(ink[1] - backdrop[1]),
          Math.abs(ink[2] - backdrop[2]));
        if (d <= 16) return 'camouflage';
      } else if (Math.min(ink[0], ink[1], ink[2]) >= 240) {
        return 'camouflage:page';
      }
    }
    return 'shown:' + Math.round(size);
  };
  const walker = document.createTreeWalker(document, NodeFilter.SHOW_TEXT);
  const re = /MARK\d+/g;
  let node;
  while ((node = walker.nextNode())) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(node.nodeValue))) {
      const range = document.createRange();
      range.setStart(node, m.index);
      range.setEnd(node, m.index + m[0].length);
      out[m[0]] = judge(node.parentElement, range);
    }
  }
  return out;
}

(async () => {
  const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const browser = await chromium.launch();
  const version = browser.version();
  const context = await browser.newContext({
    javaScriptEnabled: process.env.ORACLE_JS === '1',
    viewport: { width: 1600, height: 6000 },
  });
  await context.route('**/*', (route) => route.abort());
  let page = await context.newPage();
  const results = {};
  let n = 0;
  for (const item of cases) {
    try {
      await page.setContent(item.html, { waitUntil: 'load', timeout: 15000 });
      results[item.id] = await page.evaluate(oracle);
    } catch (error) {
      results[item.id] = { __error: String(error).slice(0, 200) };
      // A crashed renderer takes the page with it: the next document gets a new one.
      try { await page.close(); } catch (ignored) { /* already gone */ }
      page = await context.newPage();
    }
    if (++n % 500 === 0) process.stderr.write(`${n}/${cases.length}\n`);
  }
  await browser.close();
  fs.writeFileSync(process.argv[3], JSON.stringify(results));
  console.log(`rendered ${n} documents with Chromium ${version}`);
})();
