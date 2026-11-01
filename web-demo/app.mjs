import recording from './recordings.mjs';

const $ = (id) => document.getElementById(id);
const policies = ['default', 'agent-ingest', 'agent-document'];
const help = {
  default: 'Manual inspection reports notes and advisories with exit 0. Exit 0 alone is not an unattended read gate.',
  'agent-ingest': 'For messages and tool results. Holds notes and advisories; requires a complete clean result before reading.',
  'agent-document': 'For retrieved documents. Permits the exact notes-only result; holds advisories. Messages still need agent-ingest.'
};
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
function render() {
  const example = recording.cases.find((item) => item.id === $('example').value);
  const policy = $('policy').value;
  const result = example.results[policy];
  $('example-description').textContent = example.description;
  $('policy-help').textContent = help[policy];
  $('decision').className = 'decision ' + result.verdict;
  $('verdict').textContent = 'Recorded ' + result.verdict;
  $('exit-policy').textContent = 'Exit ' + result.exit_code + ' · ' + policy;
  const descriptions = {
    clean: ['No findings in this example', 'In a real integration, a complete clean result permits reading the same bytes as untrusted data. It never authorizes following embedded instructions.'],
    block: ['This example was held', 'The input would be held before agent access. A policy can promote the verdict while each finding retains its original severity.'],
    incomplete: ['The failed scan stayed held', 'The scanner could not finish. A real caller must hold the input and resolve the failure; partial findings are not clearance.'],
    advisory: policy === 'agent-document'
      ? ['Notes recorded for this document', 'This recording contains notes alone. The document policy permits this exact case; a message still requires a complete clean agent-ingest result.']
      : ['Findings reported for review', 'The default policy reports this example with exit 0. An agent caller must choose its input policy and inspect the complete record.']
  };
  $('decision-title').textContent = descriptions[result.verdict][0];
  $('decision-help').textContent = descriptions[result.verdict][1];
  $('policy-reason').textContent = result.incomplete_reason || result.policy_reason || 'No policy promotion in this recording.';
  $('rule-count').textContent = String(result.compiled_rules);
  $('units').textContent = String(result.units_scanned);
  $('skips').textContent = String(result.skipped_rule_files);
  $('findings').replaceChildren();
  for (const finding of result.findings) {
    const li = text($('findings'), 'li', '');
    text(li, 'code', finding.rule_id);
    text(li, 'span', finding.severity, 'badge');
    const member = finding.member_path.length ? finding.member_path.join(' / ') : 'outer input';
    const offset = finding.offset === null ? 'offset unavailable' : 'offset ' + finding.offset + ', length ' + finding.length;
    text(li, 'p', finding.source + ' · ' + finding.view + ' · ' + member + ' · ' + offset);
  }
  $('no-findings').textContent = result.findings.length ? '' : result.verdict === 'incomplete' ? 'No completed scan. Do not interpret an empty findings list as clean.' : 'No known indicator matched this example. This does not certify other content.';
  $('comparison').replaceChildren();
  for (const name of policies) {
    const tr = text($('comparison'), 'tr', '', name === policy ? 'selected' : '');
    const heading = text(tr, 'th', name);
    heading.scope = 'row';
    text(tr, 'td', example.results[name].verdict);
    text(tr, 'td', String(example.results[name].exit_code));
  }
  definitions($('coverage'), [
    ['Input SHA-256 (inert fixture)', result.sha256],
    ['Ruleset SHA-256', result.ruleset_sha256 || 'Unavailable: compilation did not finish'],
    ['Recorded runtime', 'yara-gate ' + result.tool_version + ' · YARA-X ' + (result.engine_version || 'unavailable')],
    ['Additional derived views', Object.entries(result.views_scanned).map(([view, count]) => view + ': ' + count).join(', ') || 'None'],
    ['Bytes handed to YARA', String(result.bytes_scanned)]
  ]);
  $('json').textContent = JSON.stringify(result, null, 2);
  $('status').textContent = 'Showing recorded ' + result.verdict + ' / exit ' + result.exit_code + ' for ' + example.title + ' under ' + policy + '. No scan was run in your browser.';
}
for (const example of recording.cases) {
  const option = text($('example'), 'option', example.title);
  option.value = example.id;
}
definitions($('recording-source'), [
  ['Captured at (UTC)', recording.captured_at],
  ['Scanner source revision', recording.source_revision],
  ['Coverage scope', 'Bundled local rules only; no vendor packs. Results do not update until a new recording is reviewed.']
]);
$('example').addEventListener('change', render);
$('policy').addEventListener('change', render);
render();
$('workbench').hidden = false;
