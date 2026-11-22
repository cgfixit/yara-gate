rule agent_base64_blob {
    meta:
        author = "yara-gate"
        description = "A base64 run of 400 or more characters, independent of filename, that is not media, a font, a PEM body, an SSH key, hex digits only, a LibreOffice printer job setup, or a token inside a web URL that does not decode to text"
        intent = "Advisory on a long base64 run whose own start is not an image, audio, video, or font header, that does not follow a data: media URI, a PEM header, or an SSH key type, and that is not hex text such as a PDF hex string or the job setup LibreOffice saves as its PrinterSetup item. A run inside an http or https URL is reported only when it decodes to written language: the rest are tracking tokens, signed parameters, and JWTs"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://datatracker.ietf.org/doc/html/rfc4648"
    condition:
        // The scanner finds runs with a linear regex (heuristics.base64_run_signals) and sets this
        // global per buffer. As a YARA string the 400-character class pattern has no atom, and
        // YARA-X verified it at every offset: about 5 s per MB of base64.
        yara_gate_b64_blob
}

rule agent_base64_executable {
    meta:
        author = "yara-gate"
        description = "A base64 run of 400 or more characters whose decoded head is a PE, ELF, or Mach-O header"
        intent = "Block an executable carried as base64 text in a page, message, JSON value, or data: URI, the encoded form of heuristic_embedded_pe"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://datatracker.ietf.org/doc/html/rfc4648"
        reference_attack = "https://attack.mitre.org/techniques/T1027/013/"
        technique = "T1027.013"
    condition:
        // Set by the scanner from the same run walk: MZ, ELF, or Mach-O magic at a run's start.
        yara_gate_b64_exe
}
