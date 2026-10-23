rule agent_eicar {
    meta:
        author = "yara-gate"
        description = "EICAR antivirus test string"
        intent = "Block the EICAR test marker"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $e
}
