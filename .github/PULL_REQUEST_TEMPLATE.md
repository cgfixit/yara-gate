## Title
**Use this format:**  
`[prefix] - Short descriptive sentence of the change`

**Recommended prefixes (pick the most relevant):**  
`[invariant]` • `[security]` • `[infra]` • `[fix]` • `[docs]` • `[harness]` • `[agentic]` • `[test]` • `[feat]`

Example: `[docs] - Retarget PR template for yara-gate`

The prefix classifies the diff. It is not a feature claim. Put commands, exit codes, and the head SHA in Further comments, not in the title.

---

## Proposed changes
Describe the big picture of your changes here. Explain **why** maintainers should accept this PR.  
If it fixes a bug or resolves a feature request, link the issue.

**Invariant / Governance Impact** (required for any change touching core paths):
- Which guarantee in `INVARIANTS.md` does this change affect (or confirm none)? Call out I6 (process isolation) and the write gates when relevant.
- Provide evidence it is preserved 
- any false positive or reduced detection for convenience risks? 
- If you are intentionally relaxing or evolving an invariant, explain the justification and compensating controls.

---

## Types of changes
What types of changes does your code introduce to this repo (`yara-gate`)?  
_Put an `x` in the boxes that apply_

- [ ] Bugfix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security (auth, encryption, certs, rbac,  privacy, injection, egress, redaction, or secrets)
- [ ] Invariant / Governance refinement (use this for changes that strengthen or evolve I6 isolation, write gates, or harness phases)
- [ ] Dependencies (updated, aligned between install methods, new deps added, removed, or bumped)
- [ ] CI / Skills / AI infrastructure (skills, workflows, hooks, lint tools, ci/cd and tests/ additions or updates/trims, templates, checkers, etc)
- [ ] Refactor or clean-up (behavior-preserving, no new capability)
- [ ] Documentation Update 
- [ ] Other (none of the boxes above fit)


**Optional free-text scope note** (recommended):  
Core isolation / write-gate path (`src/shim`, guards, writer, sandbox, workspace, shipped config) | Agentic pipeline | Console / server | Docs + audits | Infrastructure / CI only

Check a box only when the diff matches it. A docs or template edit is not a new feature. If a quality-bar command was skipped, leave the checklist row open and explain it under Risks, with the head SHA those boxes describe.

---

## Benefits / why
- Why make this change? What is the concrete upside for yara-gate / cyclaw / CGagentHarness operators, contributors, or long-term maintainability?
- How does this improve (or at least not degrade) prompt injection mitigation and or detection abilities, or security posture?

---

## Risks to monitor
- What are the potential regressions, negative side-effects, or things that need extra attention after merge?
- Could this introduce an in-process server→agentic call, default `confirm` on, weaken a write gate, create a non-loopback bind, or add a network assumption?
- For write-enablement changes: what failure modes exist if a gate is skipped or `reason` becomes optional?
- How will you (or future maintainers) detect drift from the intended behavior?

Name residual risk after the checks you actually ran. Include failed or skipped commands, their exit codes, and why you skipped them. Say which invariants the diff touches. Detect drift by re-running `scripts/check-pr-template.sh` on the body and the quality bar on the same head SHA.

---


## Suggested merge order of open PRs
_Required on every PR, including a lone one (write "independent, only open PR"). Keep every entry to 3 short lines so it reads on a phone: the PR, its impact, the action._

- **Order:** chronological (lowest PR number first) unless a real dependency exists. Name the dependency in that PR's `Impact:` line.
- **Status:** `Safe` (trial merge clean against current `main`), `Dirty` (conflicts, or stacked on something unmerged), `Blocked` (red CI, unresolved blocking review, or still a draft that is not ready).
- **Trial merge note (required):** say you verified it, with the date and the `main` SHA. Locally: `git fetch origin && git switch --detach origin/main && git merge --no-commit --no-ff origin/<branch>`, then `git merge --abort`. A "Safe" is only true until the next merge into `main`; re-run it right before merging.
- **If a PR is Dirty:** prefer a local rebase (or `git rebase --onto origin/main <old-parent-tip> <branch>` for a stacked child whose parent was squash-merged) over GitHub's "Update branch" button. Force-pushing a rebased branch is fine only on a branch that is yours alone, with `--force-with-lease`, and with the owner's OK.

```markdown
**#45** · Safe  
Impact: Base skill prompts + routing. No dependency.  
Action: Merge first. Trial merge clean vs main.

**#47** · Dirty  
Impact: Context injection; depends on #45's schema.  
Action: After #45 → rebase onto `origin/main` → `--force-with-lease` → re-verify.

Status: **Safe** applies clean to current `main`; **Dirty** conflicts; **Blocked** waits on another PR or red CI. Verify each with `git merge --no-commit --no-ff origin/<branch>` on a fresh `origin/main` checkout, then `git merge --abort`, and say so. Fix Dirty with a local rebase, not GitHub "Update branch"; on a branch someone else pushes to, merge `main` in instead. When a parent squash-merges, rebase a child with `git rebase --onto origin/main <old-parent-tip>`. A clean merge can still break: when two PRs touch one file or a `DOCS_BUDGET` cap, build and lint the merged tree. Merge a PR only when its checks are green on that head; wait for green `main` CI, then re-check the rest.

## ELI5: Merge Order
Merge the foundation first. If a later PR was written against an older base, rebase it onto the new one so it drops in clean instead of creating a merge commit. We already tested the fit with a trial merge.
```

## McLuhan tetrad
_Required on every PR and goes directly above ELI5. `pr-template-check.yml` enforces the heading, your own answer on each of the four label lines, and your own text under ELI5. Four short answers about the whole diff against `main`, later commits included. Tie each to something literal: a file, setting or command. Write N/A instead of inventing an effect._

- **Enhances:** what does this PR make stronger, faster or easier to see?
- **Obsoletes:** what does it make unnecessary or push aside?
- **Retrieves:** what does it bring back that an earlier change had dropped?
- **Reverses into:** what does it flip into when pushed to an extreme? State the actual failure, how bad it is, and the signal that shows it, worst first. List each one under Risks to monitor too.

## ELI5
_Required on every PR, and it must stay the **last heading** in the body (`pr-template-check.yml` enforces both). The body's last line you write is the stamp below (e.g. `Last updated: 2026-10-14 15:05 ET`); only a Claude Code attribution footer may follow it, and the checks strip it. Refresh the stamp whenever you edit the body._

Explain the **whole** diff against `main`, not just the first commit. Re-read it whenever a later commit changes what the PR does. Plain words, no jargon you would not say out loud, but keep the specifics:
Write for the operator: plain but technical, nothing glossed. Cover the whole branch diff against main, later commits included. Say what changed and why, naming files and functions; what could break and where to look; what was run versus only reasoned. Mark guesses. Do not market a feature or soften a gate. No heading after this one. Plain words, no jargon you would not say out loud, but keep the specifics on what is changing, what it touches, what it adds, potential or expected risk, etc. The tetrad above names the four effects; say the same thing here in plain words:

- **What was broken or missing**, in one picture or analogy, then the real names (file, function, setting) so you can still find it.
- **What changed**, including every later commit. Say what the new behavior is and what it deliberately does not do.
- **What could still go wrong**, and the exact signal that would show it (a log line, a test, an audit field).
- Be blunt about anything you did not run or could not check.

Last updated: YYYY-MM-DD HH:MM ET