rule agent_encoded_instruction {
    meta:
        author = "yara-gate"
        description = "Selected override phrases encoded in base64, including UTF-16LE source text"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://virustotal.github.io/yara-x/docs/writing_rules/text-patterns/"
    strings:
        $a = "ignore previous instructions" base64
        $b = "Ignore previous instructions" base64
        $c = "ignore all previous instructions" base64
        $d = "Ignore all previous instructions" base64
        $e = "ignore previous instructions" wide base64
        $f = "Ignore previous instructions" wide base64
    condition:
        any of them
}
