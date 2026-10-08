rule agent_base64_blob {
    meta:
        author = "yara-gate"
        description = "A base64 run of 400 or more characters, independent of filename"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://datatracker.ietf.org/doc/html/rfc4648"
    strings:
        $b = /[A-Za-z0-9+\/]{400}={0,2}/
    condition:
        $b
}
