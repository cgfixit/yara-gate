rule agent_base64_blob {
    meta:
        author = "yara-gate"
        description = "A base64 run of 400 or more characters in a text-like file"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://datatracker.ietf.org/doc/html/rfc4648"
    strings:
        $b = /[A-Za-z0-9+\/]{400}={0,2}/
    condition:
        $b and (
            yara_gate_ext == "txt" or
            yara_gate_ext == "md" or
            yara_gate_ext == "html" or
            yara_gate_ext == "htm" or
            yara_gate_ext == "json" or
            yara_gate_ext == "yaml" or
            yara_gate_ext == "yml"
        )
}
