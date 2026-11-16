# Code-relay refusal timing

[#269](https://github.com/cgfixit/yara-gate/issues/269) tracks a benign notice
that exhausted the scan deadline. The base was `8500f1925580`, using Python
3.12.12 and YARA-X 1.23.0 on arm64 macOS. Both trees loaded 89 bundled rules
with zero skips. No vendor rules were loaded.

The rule now finds request starts before, between, and after refusal matches
using YARA-X's [ordered match list and range lookup](https://github.com/VirusTotal/yara-x/blob/v1.23.0/lib/src/scanner/matches.rs).
The lookup does not traverse earlier requests. The refusal alternatives have
nondecreasing ends in start order. In particular, a nested `never` inside
`will never` runs through the same verb. Keep that property if the refusal
pattern changes. The request and refusal patterns, rule ID, and severity
are unchanged.

## Runtime

Each row is one warmed `scan_bytes` call per tree under `agent-document`
with the 30 s budget. Inputs contained ordinary meeting notes or repeated
code-relay refusals and were sliced to the exact byte size.

| Input | Size | Base seconds | Candidate seconds | Candidate result |
| --- | ---: | ---: | ---: | --- |
| Ordinary text | 1 MiB | 0.071 | 0.073 | clean |
| Repeated refusals | 1 MiB | 7.338 | 0.106 | clean |
| Ordinary text | 2 MiB | 0.137 | 0.140 | clean |
| Repeated refusals | 2 MiB | 28.696 | 0.202 | clean |
| Ordinary text | 4 MiB | 0.270 | 0.273 | clean |
| Repeated refusals | 4 MiB | 29.752, incomplete/timeout | 0.415 | clean |

The new case in `check_worst_case_timing.py` pads whole lines to exactly
4 MiB and requires a clean verdict within 10 s. It ran in 0.81 s on the
candidate and 0.49 s with #268 applied. Those runs used the default policy.

- The built wheel's CLI exercised disposable inboxes under all three policies.
  Refusal-only files, including UTF-16LE and 4 MiB ASCII, went to `clean/`
  with exit 0. A separate request on the same line remained advisory and went
  to `clean/` under default (exit 0) and `blocked/` under either agent policy
  (exit 1). The destination bytes matched the submitted bytes.
- The rule-pair, rule-coverage, detection-gap, and rule-lint checks passed. The
  328-file benign precision gate passed with no incomplete scans. The sweep
  of 1,117 installed Homebrew and standard-library text files changed zero
  findings or incomplete reasons.
- A differential run against the old condition compared rule matches, pattern IDs,
  and match offsets on 17,732 synthetic inputs. It included ASCII, UTF-16LE,
  mixed encodings, overlapping refusal starts, and long whitespace. Results
  were identical both against the base and against #268 with the fix applied.

## Browser and PR compatibility

Computer Use verified the packaged loopback demo. A 63,800-byte refusal-only
paste cleared (exit 0) and a separate request produced a hold and the advisory
finding (exit 1). Clear removed the verdict. The agent-ingest catalog matched
81 of 81 reviewed outcomes with zero findings on its 40 benign twins.

The fix applied cleanly to draft [#268](https://github.com/cgfixit/yara-gate/pull/268)
at `2fdd1a4e8098`. The combined tree passed the rule pairs, detection-gap
probe, timing case, and a second installed-file sweep compared with #268 alone.
For #268's request to return a just-sent code, the CLI reported advisory
under default and held it under both agent policies. The combined live
browser also showed the hold under `agent-ingest`.
The near-twin that tells the reader to enter the code on the sign-in page
stayed clean. The repeated-refusal paste also stayed clean. When both PRs
land, retire the old performance candidate row introduced by #268's backlog
edit and keep this record.

These are local, bundled-rule checks. They do not measure production
false positives, concurrent worker load, or Windows timing.
