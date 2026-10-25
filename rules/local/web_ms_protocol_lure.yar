rule web_ms_protocol_lure {
    meta:
        author = "yara-gate"
        description = "ms-msdt: link with diagnostic parameters or ms-appinstaller: link with a remote package source"
        intent = "Advisory on a Windows protocol link that opens MSDT with a payload or App Installer with a web package"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.microsoft.com/en-us/security/blog/2023/12/28/financially-motivated-threat-actors-misusing-app-installer/"
        reference_cve = "CVE-2022-30190"
        technique = "T1204.001"
    strings:
        // The MSDT URL carries space-separated switches, so spaces stay inside the match.
        $msdt = /\bms-msdt:[^"'<>\r\n]{0,512}(IT_BrowseForFile|IT_LaunchMethod|PCWDiagnostic|\$\()/ nocase ascii wide
        $appinstaller = /\bms-appinstaller:\?[^"'<>\s]{0,64}source=https?:\/\// nocase ascii wide
    condition:
        any of them
}
