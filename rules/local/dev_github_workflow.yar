rule dev_github_workflow_secrets_dump {
    meta:
        author = "yara-gate"
        description = "GitHub Actions workflow that serializes every repository secret and sends or re-encodes it"
        intent = "Advisory on a workflow that expands toJSON(secrets) next to a network client, a base64 encoder, or an artifact upload, the shapes the Shai-Hulud npm worm committed to victim repositories in September 2025 and its later artifact-upload variant. A workflow that only passes toJSON(secrets) to an action input, or names a single secret in an API call, stays clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"
        reference_incident = "https://xygeni.io/blog/shai-hulud-the-npm-packages-worm-explained/"
        technique = "T1552"
    strings:
        $dump = /\$\{\{[ \t]*toJSON\([ \t]*secrets[ \t]*\)[ \t]*\}\}/ nocase ascii
        $job = /(^|\n)[ \t]*(runs-on|steps)[ \t]*:/ ascii
        $send = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat)\b|\bbase64\b|webhook\.site|\bfetch\(|requests\.post|upload-artifact/ ascii
    condition:
        yara_gate_text and $job and
        for any i in (1..#dump) : ( $send in (@dump[i] - 1024..@dump[i] + 1024) )
}

rule dev_github_workflow_runner_backdoor {
    meta:
        author = "yara-gate"
        description = "GitHub Actions workflow that interpolates discussion, issue, or comment text into a shell step on a self-hosted runner"
        intent = "Advisory on a run step whose command line expands the body or title of a discussion, issue, comment, review, or pull request on a self-hosted runner, or with RUNNER_TRACKING_ID overridden so spawned processes outlive the job. The runner evidence must be in the same job as the step, or a top-level RUNNER_TRACKING_ID. Anyone who can open a discussion or issue then runs commands on that machine; Shai-Hulud 2.0 registered victims as runners and committed this shape as discussion.yaml. Interpolation on a GitHub-hosted runner is the common injection weakness, not a planted backdoor, and stays clean here, as do env:, with:, and if: values that read the same fields, including an env: that follows a block-scalar run"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://securitylab.github.com/resources/github-actions-untrusted-input/"
        reference_incident = "https://www.sysdig.com/blog/how-threat-actors-are-using-self-hosted-github-actions-runners-as-backdoors"
        technique = "T1059.004"
    strings:
        // A single-line run whose command text contains the event field.
        $run = /(^|\n)[ \t]*(-[ \t]+)?run[ \t]*:[ \t]*[^\r\n|>][^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        // A block-scalar run whose next lines contain the event field. YAML ends the scalar at the
        // first line indented no deeper than the run key, so each string fixes the key's column
        // (dash form or plain) and requires every following line to be deeper or blank. A sibling
        // env: or with: that carries the field is therefore not part of the shell text.
        $block2 = /(^|\n)( {0}- | {2})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {3}[^\r\n]{0,200})?\r?\n){0,8} {3}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block4 = /(^|\n)( {2}- | {4})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {5}[^\r\n]{0,200})?\r?\n){0,8} {5}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block6 = /(^|\n)( {4}- | {6})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {7}[^\r\n]{0,200})?\r?\n){0,8} {7}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block8 = /(^|\n)( {6}- | {8})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {9}[^\r\n]{0,200})?\r?\n){0,8} {9}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block10 = /(^|\n)( {8}- | {10})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {11}[^\r\n]{0,200})?\r?\n){0,8} {11}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block12 = /(^|\n)( {10}- | {12})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {13}[^\r\n]{0,200})?\r?\n){0,8} {13}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block14 = /(^|\n)( {12}- | {14})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {15}[^\r\n]{0,200})?\r?\n){0,8} {15}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block16 = /(^|\n)( {14}- | {16})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {17}[^\r\n]{0,200})?\r?\n){0,8} {17}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block18 = /(^|\n)( {16}- | {18})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {19}[^\r\n]{0,200})?\r?\n){0,8} {19}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $block20 = /(^|\n)( {18}- | {20})run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n(( {21}[^\r\n]{0,200})?\r?\n){0,8} {21}[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $self_hosted = /(^|\n)[ \t]*runs-on[ \t]*:[ \t]*(\[[ \t]*)?['"]?self-hosted\b/ ascii
        // The runner kills a job's leftover processes by this id; any override lets them outlive the job.
        $untracked = /(^|\n)[ \t]*RUNNER_TRACKING_ID[ \t]*:/ ascii
        $jobs = /(^|\n)jobs[ \t]*:/ ascii
        // A job header: a key at indent 2 to 4 whose next line opens with a job-level key.
        $job = /\n {2,4}[A-Za-z_][A-Za-z0-9_-]*[ \t]*:[ \t]*(#[^\r\n]*)?\r?\n {4,8}(runs-on|steps|needs|if|name|env|strategy|permissions|environment|container|services|outputs|timeout-minutes|continue-on-error|concurrency|defaults|uses|with|secrets)[ \t]*:/ ascii
    condition:
        // The runner evidence must sit in the same job as the step, before it with no job header in
        // between, or be a top-level RUNNER_TRACKING_ID before jobs:, which applies to every job.
        // The first 32 evidence lines are tried, which keeps the cost linear in the step matches.
        yara_gate_text and
        (
            for any j in (1..#self_hosted) : (
                j <= 32 and for any of ($run, $block*) : (
                    for any i in (1..#) : ( @[i] > @self_hosted[j] and #job in (@self_hosted[j]..@[i]) == 0 )
                )
            ) or
            for any j in (1..#untracked) : (
                j <= 32 and (
                    (#jobs > 0 and @untracked[j] < @jobs[1] and any of ($run, $block*)) or
                    for any of ($run, $block*) : (
                        for any i in (1..#) : ( @[i] > @untracked[j] and #job in (@untracked[j]..@[i]) == 0 )
                    )
                )
            )
        )
}
