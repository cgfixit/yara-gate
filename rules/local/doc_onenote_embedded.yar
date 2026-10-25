rule doc_onenote_embedded_launcher {
    meta:
        author = "yara-gate"
        description = "OneNote section whose embedded file store starts with an executable, a shortcut, or script text"
        intent = "Advisory on a .one notebook that carries an exe, lnk, HTA, VBS, JS, batch, or PowerShell attachment"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/"
        technique = "T1566.001"
    strings:
        // MS-ONESTORE FileDataStoreObject header GUID {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}.
        // Its data begins 36 bytes later: GUID, cbLength, unused, reserved.
        $store = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }
        $script = /(<html|<hta:|<script|@echo|WScript\.Shell|powershell|On Error Resume Next|CreateObject\(|ActiveXObject\()/ nocase ascii wide
    condition:
        // The .one file header GUID {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}.
        uint32(0) == 0x7B5C52E4 and uint32(4) == 0x4DA7D88C and
        for any i in (1..#store) : (
            uint16(@store[i] + 36) == 0x5A4D or
            uint32(@store[i] + 36) == 0x0000004C or
            $script in (@store[i] + 36..@store[i] + 100)
        )
}
