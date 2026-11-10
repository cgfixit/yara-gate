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
const kindTag = { detection: 'Attack', control: 'Benign twin', failure: 'Fail-closed case' };
// Plain-language names for the derived views a finding can come from.
const viewNames = {
  raw: 'the original bytes',
  'text-folded': 'the text with small capitals, look-alike letters, digits, spacing, and terminal escapes folded',
  'format-controls-removed': 'the text with invisible formatting characters removed',
  'html-unescaped': 'the text with HTML character references decoded',
  'json-unescaped': 'the text with JSON string escapes decoded',
  'base64-decoded': 'one decoded base64 run, read on its own',
  'percent-decoded': 'the text with percent-encoding decoded',
  'mime-headers-decoded': 'the decoded email headers',
  'decoded-utf16': 'the text decoded from UTF-16',
  'ooxml-text': 'the joined text of an Office document',
  'ooxml-cell': 'one spreadsheet cell with its rich-text runs rejoined',
  'ooxml-comment': 'one Office comment with its text runs rejoined',
  'ooxml-hidden-text': 'Office text a reader does not show (hidden, white, or 1 pt)',
  'pdf-hidden-text': 'PDF text a viewer does not paint (invisible mode, white, tiny, or off the page)',
  'pdf-annotation': 'one PDF annotation with its text string decoded',
  'rtf-text': 'one RTF paragraph with formatting and character escapes decoded',
  'html-text': 'one HTML block or SVG text element with its inline text rejoined',
  'markdown-text': 'one Markdown paragraph with its inline markup removed',
  'notebook-text': 'one notebook cell with its lines rejoined',
  'comment-text': 'consecutive source comment lines rejoined',
  'pdf-flate': 'an inflated PDF stream',
  'pdf-text': 'one PDF text block, read through its font maps',
  'pdf-paragraph': 'a PDF paragraph rejoined across text blocks'
};
const sources = {
  yara: 'YARA rule matched ',
  heuristic: 'Structural check, no YARA rule, found it ',
  filetype: 'File-type check found it '
};
const folded = '+text-folded';
const byId = new Map(recording.cases.map((item) => [item.id, item]));
const state = { example: 'xlsx_comment_override', policy: 'agent-ingest', channel: 'All', method: 'All' };

// How an attack was caught, read from its recorded agent-ingest findings: which view or check
// produced a finding that the bytes as sent did not. Nothing here is labelled by hand.
const methodNames = {
  hidden: 'Hidden from the reader',
  folded: 'Disguised spelling',
  rebuilt: 'Split across formatting',
  decoded: 'Encoded',
  container: 'Inside an archive',
  structure: 'File structure',
  pattern: 'Plain pattern'
};
const rebuiltViews = new Set(['ooxml-text', 'ooxml-cell', 'ooxml-comment', 'html-text', 'markdown-text', 'notebook-text', 'comment-text', 'pdf-text', 'pdf-paragraph', 'rtf-text']);
function methodsOf(item) {
  const findings = item.results['agent-ingest'].findings;
  const tags = new Set();
  // A rule that already matched the bytes as sent needed no derived view.
  const plain = new Set(findings.filter((finding) => finding.view === 'raw').map((finding) => finding.rule_id));
  for (const finding of findings) {
    const base = finding.view.endsWith(folded) ? finding.view.slice(0, -folded.length) : finding.view;
    if (finding.view.includes('hidden') || finding.rule_id.includes('hidden')) tags.add('hidden');
    else if (finding.source !== 'yara') tags.add('structure');
    else if (!plain.has(finding.rule_id)) {
      if (finding.view !== base || base === 'text-folded') tags.add('folded');
      if (rebuiltViews.has(base)) tags.add('rebuilt');
      else if (base !== 'text-folded') tags.add('decoded');
    }
  }
  if (!tags.size && findings.some((finding) => finding.member_path.length)) tags.add('container');
  if (!tags.size) tags.add('pattern');
  return Object.keys(methodNames).filter((key) => tags.has(key));
}

// Fictional context only. Decisions always come from the selected fixture's recording.
const stories = [
  { id: 'xlsx_comment_override', label: 'Supplier review', title: 'Summarize a supplier workbook',
    brief: 'The procurement assistant is asked to summarize review comments. One comment hides an override across formatting runs; its twin discusses quarterly totals.',
    sender: 'supplier@example.invalid', task: 'Procurement · review comments', file: 'review.xlsx' },
  { id: 'ansi_log', label: 'Build triage', title: 'Explain a failed build',
    brief: 'A coding assistant receives a coloured CI log. A terminal escape sits against an instruction in the suspicious version; the twin keeps an ordinary build summary.',
    sender: 'Example CI · simulated tool response', task: 'Engineering · build triage', file: 'build.log' },
  { id: 'svg_cdata_override', label: 'Design handoff', title: 'Read a supplied design asset',
    brief: 'An assistant checks an SVG attachment. The suspicious label splits a directive across CDATA and a span; its twin uses the same layout for an ordinary chart label.',
    sender: 'design@example.invalid', task: 'Design · attachment review', file: 'logo.svg' },
  { id: 'pickle_call', label: 'Model intake', title: 'Inspect a checkpoint before loading',
    brief: 'A model file arrives for evaluation. Static inspection finds an os.system call in the synthetic pickle; the twin rebuilds ordinary state with OrderedDict. Neither is unpickled.',
    sender: 'Example model catalog · dummy artifact', task: 'ML · artifact intake', file: 'model.pt' },
  { id: 'devcontainer', label: 'Repository intake', title: 'Review a development environment',
    brief: 'A repository asks to initialize a dev container. The suspicious config downloads and runs a script on the host; the twin creates a host folder and installs inside the container.',
    sender: 'Example repository · dummy checkout', task: 'Engineering · environment review', file: 'devcontainer.json' },
  { id: 'mcp_tool_poisoned', label: 'Tool onboarding', title: 'Review a new tool server',
    brief: 'An agent platform lists the tools of a new MCP server. One description, 58th of 60, tells the model to read a private key and stay quiet; the twin lists sixty ordinary tools. No server is contacted.',
    sender: 'Example tool server · simulated response', task: 'Platform · tool review', file: 'tools.json' },
  { id: 'pdf_invisible_override', label: 'Invoice intake', title: 'Read a supplier invoice',
    brief: 'A finance assistant reads a PDF invoice. One line is drawn as invisible text and carries an instruction; the twin carries an ordinary invisible text layer, as a scanned page does.',
    sender: 'billing@example.invalid', task: 'Finance · invoice intake', file: 'invoice.pdf' }
];

function storyButtons() {
  for (const story of stories) {
    const button = text($('stories'), 'button', story.label, 'story-button');
    button.type = 'button';
    button.dataset.example = story.id;
    button.addEventListener('click', () => {
      state.policy = 'agent-ingest';
      select(story.id, false);
    });
  }
}

function storyContext(example) {
  const story = stories.find((item) => item.id === example.id || item.id === example.pair);
  $('story-context').hidden = !story;
  for (const button of document.querySelectorAll('.story-button')) {
    button.setAttribute('aria-pressed', String(button.dataset.example === story?.id));
  }
  if (!story) return;
  $('story-title').textContent = story.title;
  $('story-brief').textContent = story.brief;
  definitions($('story-envelope'), [['From (fictional)', story.sender], ['Task', story.task], ['Fixture filename', story.file]]);
}

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
  // A decoded or rejoined view can be folded once more, so stacked evasions are read together.
  if (view.endsWith(folded)) return viewName(view.slice(0, -folded.length)) + ', then folded for look-alikes and digits';
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
  const twinFindings = controls.reduce((sum, item) => sum + policies.reduce((count, policy) => count + item.results[policy].findings.length, 0), 0);
  const sample = cases.find((item) => item.kind !== 'failure').results.default;
  $('score-held').textContent = held + ' / ' + detections.length;
  $('score-held-label').textContent = 'attacks held under agent-ingest';
  $('score-clean').textContent = clean + ' / ' + controls.length;
  $('score-clean-label').textContent = 'benign twins clean under every policy';
  $('score-findings').textContent = String(twinFindings);
  $('score-findings-label').textContent = 'findings across ' + controls.length * policies.length + ' benign-twin recordings';
  $('score-failure').textContent = stayed + ' / ' + failures.length;
  $('score-failure-label').textContent = 'unfinished scans held as incomplete';
  $('score-rules').textContent = String(sample.compiled_rules);
  $('score-rules-label').textContent = 'bundled rules · YARA-X ' + sample.engine_version;
  $('scoreboard').hidden = false;
}

const marks = { block: '✕', clean: '✓', advisory: '!', incomplete: '?' };
function strip() {
  const root = $('strip');
  for (const item of recording.cases) {
    if (item.kind === 'control') continue;
    const column = text(root, 'span', '', 'strip-col');
    for (const member of item.pair ? [item, byId.get(item.pair)] : [item]) {
      const cell = text(column, 'button', '', 'cell');
      cell.type = 'button';
      cell.dataset.example = member.id;
      cell.addEventListener('click', () => select(member.id, true));
    }
  }
}
function renderStrip() {
  const policy = state.policy;
  let held = 0;
  let clean = 0;
  for (const cell of document.querySelectorAll('.cell')) {
    const item = byId.get(cell.dataset.example);
    const verdict = item.results[policy].verdict;
    cell.className = 'cell ' + verdict;
    cell.textContent = marks[verdict];
    cell.setAttribute('aria-label', kindTag[item.kind] + ': ' + item.title + '. Recorded ' + verdict + ' under ' + policy + '.');
    cell.title = kindTag[item.kind] + ' · ' + item.title + ' · ' + verdict;
    cell.setAttribute('aria-pressed', String(item.id === state.example));
    if (item.kind === 'detection' && verdict === 'block') held += 1;
    if (item.kind === 'control' && verdict === 'clean') clean += 1;
  }
  const pairs = recording.cases.filter((item) => item.kind === 'detection').length;
  const rest = pairs - held;
  $('evidence-policy').textContent = policy;
  $('evidence-summary').textContent = 'Under ' + policy + ': ' + held + ' of ' + pairs + ' attacks held, ' + clean + ' of ' + pairs + ' benign twins clean.'
    + (rest ? ' The other ' + rest + ' attack' + (rest === 1 ? ' is' : 's are') + ' reported with findings and exit 0' + (policy === 'agent-document' ? ', because a retrieved document may quote an override phrase.' : ', because this policy is for manual inspection.') : '');
}

function caseButton(parent, item) {
  const card = text(parent, 'button', '', 'card ' + item.kind);
  card.type = 'button';
  card.dataset.example = item.id;
  text(card, 'span', kindTag[item.kind], 'card-kind');
  text(card, 'span', item.title, 'card-title');
  if (item.kind === 'detection') text(card, 'span', 'Caught: ' + methodsOf(item).map((key) => methodNames[key].toLowerCase()).join(' + '), 'card-how');
  const chips = text(card, 'span', '', 'chips');
  for (const policy of policies) chip(chips, item.results[policy].verdict, policyLabels[policy][1]);
  card.addEventListener('click', () => select(item.id, true));
}

// One row per attack and its benign twin, attack first; the failure stands alone.
function gallery() {
  const root = $('gallery');
  const placed = new Set();
  for (const item of recording.cases) {
    if (placed.has(item.id)) continue;
    const twin = item.pair ? byId.get(item.pair) : null;
    const members = !twin ? [item] : item.kind === 'detection' ? [item, twin] : [twin, item];
    const row = text(root, 'div', '', 'pair' + (twin ? '' : ' single'));
    row.dataset.channel = item.channel;
    row.dataset.methods = members[0].kind === 'detection' ? methodsOf(members[0]).join(' ') : '';
    text(row, 'span', item.channel, 'channel');
    const halves = text(row, 'div', '', 'halves');
    for (const member of members) {
      placed.add(member.id);
      caseButton(halves, member);
    }
  }
}

function filterButtons(root, key, entries) {
  for (const [value, label] of entries) {
    const button = text(root, 'button', label, 'filter');
    button.type = 'button';
    button.dataset[key] = value;
    button.addEventListener('click', () => {
      state[key] = value;
      applyFilter();
    });
  }
}

function galleryFilters() {
  const rows = Array.from(document.querySelectorAll('.pair'));
  const channels = new Map();
  for (const row of rows) channels.set(row.dataset.channel, (channels.get(row.dataset.channel) || 0) + 1);
  filterButtons($('channels'), 'channel', [['All', 'All · ' + rows.length], ...Array.from(channels, ([channel, count]) => [channel, channel + ' · ' + count])]);
  const used = Object.keys(methodNames).filter((key) => rows.some((row) => row.dataset.methods.split(' ').includes(key)));
  filterButtons($('methods'), 'method', [['All', 'Any'], ...used.map((key) => [key, methodNames[key] + ' · ' + rows.filter((row) => row.dataset.methods.split(' ').includes(key)).length])]);
  applyFilter();
}

function applyFilter() {
  let shown = 0;
  for (const row of document.querySelectorAll('.pair')) {
    row.hidden = (state.channel !== 'All' && row.dataset.channel !== state.channel)
      || (state.method !== 'All' && !row.dataset.methods.split(' ').includes(state.method));
    if (!row.hidden) shown += 1;
  }
  for (const button of document.querySelectorAll('#channels .filter')) button.setAttribute('aria-pressed', String(button.dataset.channel === state.channel));
  for (const button of document.querySelectorAll('#methods .filter')) button.setAttribute('aria-pressed', String(button.dataset.method === state.method));
  $('gallery-count').textContent = shown ? 'Showing ' + shown + ' recorded row' + (shown === 1 ? '' : 's') + '.' : 'No recorded pair matches both filters.';
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
  if (scroll) $('result-title').focus();
}

function render() {
  const example = byId.get(state.example);
  const policy = state.policy;
  const result = example.results[policy];
  storyContext(example);
  for (const card of document.querySelectorAll('.card')) card.setAttribute('aria-pressed', String(card.dataset.example === example.id));
  for (const button of document.querySelectorAll('.segment')) button.setAttribute('aria-pressed', String(button.dataset.policy === policy));
  $('policy-help').textContent = help[policy];
  $('example-title').textContent = example.title;
  $('example-kind').textContent = kindTag[example.kind];
  $('example-kind').className = 'tag kind-' + example.kind;
  $('example-channel').textContent = example.channel;
  $('example-description').textContent = example.description;
  $('example-how').replaceChildren();
  const attack = example.kind === 'detection' ? example : example.pair ? byId.get(example.pair) : null;
  if (attack) {
    text($('example-how'), 'span', example.kind === 'detection' ? 'Caught:' : 'Its attack was caught:', 'how-label');
    for (const key of methodsOf(attack)) text($('example-how'), 'span', methodNames[key], 'tag');
  }
  $('decision').className = 'decision ' + result.verdict;
  $('verdict').textContent = 'Recorded ' + result.verdict;
  $('exit-policy').textContent = 'Exit ' + result.exit_code + ' · ' + policy;
  const descriptions = {
    clean: example.kind === 'control'
      ? ['Passed: a benign twin with no findings', 'The same channel and shape as an attack, with ordinary content. A complete clean result lets a real integration read these exact bytes as untrusted data.']
      : ['No findings in this example', 'In a real integration, a complete clean result permits reading the same bytes as untrusted data. It never authorizes following embedded instructions.'],
    block: ['Held before the agent reads it', 'The input would be held before agent access. A policy can promote the verdict while each finding keeps its original severity.'],
    incomplete: ['The unfinished scan stayed held', 'The scanner could not finish. A real caller must hold the input and resolve the failure; partial findings are not clearance.'],
    advisory: policy === 'agent-document'
      ? ['Notes recorded for this document', 'This recording contains notes alone. The document policy permits this exact case; a message still requires a complete clean agent-ingest result.']
      : ['Findings reported for review', 'The default policy reports this example with exit 0. An agent caller must choose its input policy and inspect the complete record.']
  };
  $('decision-title').textContent = descriptions[result.verdict][0];
  $('decision-help').textContent = descriptions[result.verdict][1];
  $('policy-reason').textContent = result.incomplete_reason
    ? 'Incomplete: ' + result.incomplete_reason
    : result.policy_reason || 'No policy promotion in this recording.';
  $('findings-title').textContent = result.findings.length ? 'What triggered the decision' : 'What the scanner found';
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
  renderStrip();
  $('status').textContent = 'Showing recorded ' + result.verdict + ' / exit ' + result.exit_code + ' for ' + example.title + ' under ' + policy + '. No scan was run in your browser.';
}

scoreboard();
strip();
storyButtons();
gallery();
galleryFilters();
policyButtons();
$('twin-open').addEventListener('click', () => {
  const pair = byId.get(state.example).pair;
  if (pair) select(pair, false);
});
$('revision').textContent = 'Recorded from ' + recording.source_revision.slice(0, 12) + ' · ' + recording.captured_at.slice(0, 10) + ' UTC · bundled rules only';
definitions($('recording-source'), [
  ['Captured at (UTC)', recording.captured_at],
  ['Scanner source revision', recording.source_revision],
  ['Coverage scope', 'Bundled local rules only; no vendor packs. The deploy pipeline re-records from its source revision; verdicts and findings must match the reviewed baseline, or the deploy stops.']
]);
render();
$('workbench').hidden = false;
