import recording from './recordings.mjs';

const $ = (id) => document.getElementById(id);
// The agent policies first; the chips on each card use the same order.
const policies = ['agent-ingest', 'agent-document', 'default'];
const policyLabels = {
  'agent-ingest': ['Message or tool result', 'agent-ingest'],
  'agent-document': ['Synced document', 'agent-document'],
  default: ['Manual inspection', 'default']
};
const help = {
  default: 'Manual inspection reports notes and advisories with exit 0. Exit 0 alone is not an unattended read gate.',
  'agent-ingest': 'For messages and tool results. Holds notes and advisories; requires a complete clean result before reading.',
  'agent-document': 'For retrieved documents. Permits the exact notes-only result; holds advisories. Messages still need agent-ingest.'
};
const kinds = {
  detection: ['Attacks', 'Held before the agent reads them.'],
  control: ['Benign twins', 'Same shape as an attack, ordinary content. Recorded clean under every policy.'],
  failure: ['Failure handling', 'A scan that cannot finish is held, never passed.']
};
const kindTag = { detection: 'Attack', control: 'Benign twin', failure: 'Failure' };
// Plain-language names for the derived views a finding can come from.
const viewNames = {
  raw: 'the original bytes',
  'text-folded': 'the text with look-alike letters and spacing folded',
  'html-unescaped': 'the text with HTML character references decoded',
  'json-unescaped': 'the text with JSON string escapes decoded',
  'base64-decoded': 'one decoded base64 run, read on its own',
  'percent-decoded': 'the text with percent-encoding decoded',
  'mime-headers-decoded': 'the decoded email headers',
  'decoded-utf16': 'the text decoded from UTF-16',
  'ooxml-text': 'the joined text of an Office document',
  'pdf-flate': 'an inflated PDF stream',
  'pdf-text': 'one PDF text block, read through its font maps',
  'pdf-paragraph': 'a PDF paragraph rejoined across text blocks'
};
const sources = {
  yara: 'YARA rule matched ',
  heuristic: 'Structural check, no YARA rule, found it ',
  filetype: 'File-type check found it '
};
const byId = new Map(recording.cases.map((item) => [item.id, item]));
const state = { example: recording.cases[0].id, policy: 'agent-ingest' };

function text(parent, tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  parent.append(element);
  return element;
}
function definitions(parent, entries) {
  parent.replaceChildren();
  for (const [label, value] of entries) {
    text(parent, 'dt', label);
    text(parent, 'dd', value);
  }
}
function viewName(view) {
  return viewNames[view] || 'the ' + view + ' view';
}
function where(finding) {
  const member = finding.member_path.length
    ? 'inside archive member ' + finding.member_path.map((step) => Number(step.split(':')[1]) + 1).join(' → ')
    : 'in the outer input';
  const offset = finding.offset === null ? '' : ' at offset ' + finding.offset + ' (length ' + finding.length + ')';
  const view = finding.member_path.length && finding.view === 'raw' ? "the member's own bytes" : viewName(finding.view);
  return member + ', ' + view + offset;
}
function chip(parent, verdict, label) {
  const element = text(parent, 'span', verdict, 'chip ' + verdict);
  element.title = label + ': ' + verdict;
  return element;
}

function scoreboard() {
  const cases = recording.cases;
  const detections = cases.filter((item) => item.kind === 'detection');
  const controls = cases.filter((item) => item.kind === 'control');
  const failures = cases.filter((item) => item.kind === 'failure');
  const held = detections.filter((item) => item.results['agent-ingest'].verdict === 'block').length;
  const clean = controls.filter((item) => policies.every((policy) => item.results[policy].verdict === 'clean' && item.results[policy].findings.length === 0)).length;
  const stayed = failures.filter((item) => policies.every((policy) => item.results[policy].verdict === 'incomplete')).length;
  const sample = cases.find((item) => item.kind !== 'failure').results.default;
  $('score-held').textContent = held + ' / ' + detections.length;
  $('score-held-label').textContent = 'attacks held under agent-ingest';
  $('score-clean').textContent = clean + ' / ' + controls.length;
  $('score-clean-label').textContent = 'benign twins clean, zero findings, every policy';
  $('score-failure').textContent = stayed + ' / ' + failures.length;
  $('score-failure-label').textContent = 'failed scan held as incomplete';
  $('score-rules').textContent = String(sample.compiled_rules);
  $('score-rules-label').textContent = 'bundled rules · YARA-X ' + sample.engine_version;
  $('scoreboard').hidden = false;
}

function gallery() {
  const root = $('gallery');
  for (const kind of ['detection', 'control', 'failure']) {
    const group = text(root, 'div', '', 'group');
    text(group, 'h3', kinds[kind][0]);
    text(group, 'p', kinds[kind][1], 'help');
    const list = text(group, 'div', '', 'cards');
    for (const item of recording.cases.filter((entry) => entry.kind === kind)) {
      const card = text(list, 'button', '', 'card ' + kind);
      card.type = 'button';
      card.dataset.example = item.id;
      text(card, 'span', item.channel, 'channel');
      text(card, 'span', item.title, 'card-title');
      const chips = text(card, 'span', '', 'chips');
      for (const policy of policies) chip(chips, item.results[policy].verdict, policyLabels[policy][1]);
      if (item.pair) text(card, 'span', kind === 'control' ? 'Twin of an attack' : 'Has a benign twin', 'pair-note');
      card.addEventListener('click', () => select(item.id, true));
    }
  }
}

function policyButtons() {
  for (const policy of policies) {
    const button = text($('policy'), 'button', '', 'segment');
    button.type = 'button';
    button.dataset.policy = policy;
    text(button, 'span', policyLabels[policy][0]);
    text(button, 'code', policyLabels[policy][1]);
    button.addEventListener('click', () => {
      state.policy = policy;
      render();
    });
  }
}

function twinColumn(parent, item, policy, isSelected) {
  const result = item.results[policy];
  const column = text(parent, 'div', '', 'twin-col ' + item.kind + (isSelected ? ' current' : ''));
  text(column, 'span', kindTag[item.kind], 'tag');
  text(column, 'strong', item.title);
  const line = text(column, 'p', '');
  chip(line, result.verdict, policy);
  text(line, 'span', ' exit ' + result.exit_code);
  text(column, 'p', result.findings.length
    ? result.findings.map((finding) => finding.rule_id).join(', ')
    : 'No findings', 'help');
}

function select(id, scroll) {
  state.example = id;
  render();
  if (scroll && window.matchMedia('(max-width: 800px)').matches) $('result-title').focus();
}

function render() {
  const example = byId.get(state.example);
  const policy = state.policy;
  const result = example.results[policy];
  for (const card of document.querySelectorAll('.card')) card.setAttribute('aria-pressed', String(card.dataset.example === example.id));
  for (const button of document.querySelectorAll('.segment')) button.setAttribute('aria-pressed', String(button.dataset.policy === policy));
  $('policy-help').textContent = help[policy];
  $('example-title').textContent = example.title;
  $('example-kind').textContent = kindTag[example.kind];
  $('example-kind').className = 'tag kind-' + example.kind;
  $('example-channel').textContent = example.channel;
  $('example-description').textContent = example.description;
  $('decision').className = 'decision ' + result.verdict;
  $('verdict').textContent = 'Recorded ' + result.verdict;
  $('exit-policy').textContent = 'Exit ' + result.exit_code + ' · ' + policy;
  const descriptions = {
    clean: example.kind === 'control'
      ? ['Passed: a benign twin with no findings', 'The same channel and shape as an attack, with ordinary content. A complete clean result lets a real integration read these exact bytes as untrusted data.']
      : ['No findings in this example', 'In a real integration, a complete clean result permits reading the same bytes as untrusted data. It never authorizes following embedded instructions.'],
    block: ['Held before the agent reads it', 'The input would be held before agent access. A policy can promote the verdict while each finding keeps its original severity.'],
    incomplete: ['The failed scan stayed held', 'The scanner could not finish. A real caller must hold the input and resolve the failure; partial findings are not clearance.'],
    advisory: policy === 'agent-document'
      ? ['Notes recorded for this document', 'This recording contains notes alone. The document policy permits this exact case; a message still requires a complete clean agent-ingest result.']
      : ['Findings reported for review', 'The default policy reports this example with exit 0. An agent caller must choose its input policy and inspect the complete record.']
  };
  $('decision-title').textContent = descriptions[result.verdict][0];
  $('decision-help').textContent = descriptions[result.verdict][1];
  $('policy-reason').textContent = result.incomplete_reason
    ? 'Incomplete: ' + result.incomplete_reason
    : result.policy_reason || 'No policy promotion in this recording.';
  $('findings').replaceChildren();
  for (const finding of result.findings) {
    const li = text($('findings'), 'li', '');
    const head = text(li, 'p', '', 'finding-head');
    text(head, 'code', finding.rule_id);
    text(head, 'span', finding.severity, 'badge ' + finding.severity);
    text(li, 'p', (sources[finding.source] || finding.source + ' check: found ') + where(finding) + '.');
  }
  $('no-findings').textContent = result.findings.length
    ? ''
    : result.verdict === 'incomplete'
      ? 'No completed scan. Do not read an empty findings list as clean.'
      : 'Nothing matched, though the scanner read ' + (Object.keys(result.views_scanned).length ? Object.keys(result.views_scanned).map(viewName).join('; ') : 'the original bytes') + '. This does not certify other content.';
  const twin = example.pair ? byId.get(example.pair) : null;
  $('twin').hidden = !twin;
  if (twin) {
    $('twin-grid').replaceChildren();
    const [attack, control] = example.kind === 'detection' ? [example, twin] : [twin, example];
    twinColumn($('twin-grid'), attack, policy, attack === example);
    twinColumn($('twin-grid'), control, policy, control === example);
    $('twin-open').textContent = 'Show the ' + (twin.kind === 'control' ? 'benign twin' : 'attack') + ' →';
  }
  $('comparison').replaceChildren();
  for (const name of policies) {
    const tr = text($('comparison'), 'tr', '', name === policy ? 'selected' : '');
    const heading = text(tr, 'th', name);
    heading.scope = 'row';
    chip(text(tr, 'td', ''), example.results[name].verdict, name);
    text(tr, 'td', String(example.results[name].exit_code));
  }
  $('rule-count').textContent = String(result.compiled_rules);
  $('units').textContent = String(result.units_scanned);
  $('views').textContent = String(Object.values(result.views_scanned).reduce((sum, count) => sum + count, 0));
  definitions($('coverage'), [
    ['Input SHA-256 (inert fixture)', result.sha256],
    ['Ruleset SHA-256', result.ruleset_sha256 || 'Unavailable: compilation did not finish'],
    ['Recorded runtime', 'yara-gate ' + result.tool_version + ' · YARA-X ' + (result.engine_version || 'unavailable')],
    ['Derived views read', Object.entries(result.views_scanned).map(([view, count]) => view + ': ' + count).join(', ') || 'None beyond the original bytes'],
    ['Skipped rule files', String(result.skipped_rule_files)],
    ['Bytes handed to YARA', String(result.bytes_scanned)]
  ]);
  $('json').textContent = JSON.stringify(result, null, 2);
  $('status').textContent = 'Showing recorded ' + result.verdict + ' / exit ' + result.exit_code + ' for ' + example.title + ' under ' + policy + '. No scan was run in your browser.';
}

scoreboard();
gallery();
policyButtons();
$('twin-open').addEventListener('click', () => {
  const pair = byId.get(state.example).pair;
  if (pair) select(pair, false);
});
definitions($('recording-source'), [
  ['Captured at (UTC)', recording.captured_at],
  ['Scanner source revision', recording.source_revision],
  ['Coverage scope', 'Bundled local rules only; no vendor packs. Re-recorded from this revision when the page was deployed; verdicts and findings must match the reviewed baseline, or the deploy stops.']
]);
render();
$('workbench').hidden = false;
