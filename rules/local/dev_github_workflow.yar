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
        intent = "Advisory on a run step whose command line expands the body or title of a discussion, issue, comment, review, or pull request on a self-hosted runner, or with RUNNER_TRACKING_ID overridden so spawned processes outlive the job. Anyone who can open a discussion or issue then runs commands on that machine; Shai-Hulud 2.0 registered victims as runners and committed this shape as discussion.yaml. Interpolation on a GitHub-hosted runner is the common injection weakness, not a planted backdoor, and stays clean here, as do with: inputs and if: conditions that read the same fields"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://securitylab.github.com/resources/github-actions-untrusted-input/"
        reference_incident = "https://www.sysdig.com/blog/how-threat-actors-are-using-self-hosted-github-actions-runners-as-backdoors"
        technique = "T1059.004"
    strings:
        // A single-line run whose command text contains the event field.
        $run = /(^|\n)[ \t]*(-[ \t]+)?run[ \t]*:[ \t]*[^\r\n|>][^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        // A block-scalar run whose next lines contain the event field.
        $block = /(^|\n)[ \t]*(-[ \t]+)?run[ \t]*:[ \t]*[|>][-+0-9]*[ \t]*\r?\n([ \t]+[^\r\n]{0,200}\r?\n){0,8}[ \t]+[^\r\n]{0,200}\$\{\{[ \t]*github\.event\.(discussion|issue|comment|review|review_comment|pull_request)\.(body|title)[ \t]*\}\}/ ascii
        $self_hosted = /(^|\n)[ \t]*runs-on[ \t]*:[ \t]*(\[[ \t]*)?['"]?self-hosted\b/ ascii
        // The runner kills a job's leftover processes by this id; any override lets them outlive the job.
        $untracked = /(^|\n)[ \t]*RUNNER_TRACKING_ID[ \t]*:/ ascii
    condition:
        yara_gate_text and ($run or $block) and ($self_hosted or $untracked)
}
