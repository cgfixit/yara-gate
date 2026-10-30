rule macos_gatekeeper_disable {
    meta:
        author = "yara-gate"
        description = "Command that turns Gatekeeper off or stops Launch Services from quarantining downloads"
        intent = "Advisory on spctl --master-disable or --global-disable and the LSQuarantine default set to false, the step a stealer installer asks for before it runs"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web"
        reference_attack = "https://attack.mitre.org/techniques/T1553/001/"
        technique = "T1553.001"
    strings:
        $spctl = /\bspctl[ \t]+(--master-disable|--global-disable)\b/ nocase ascii wide
        $lsquarantine = /\bdefaults[ \t]+write[ \t]+com\.apple\.LaunchServices[ \t]+["']?LSQuarantine["']?[ \t]+(-bool[ \t]+)?(NO|false|0)\b/ nocase ascii wide
    condition:
        any of them
}

rule macos_archive_upload {
    meta:
        author = "yara-gate"
        description = "ditto archive of a folder followed by a curl form or binary upload of a file"
        intent = "Advisory on the AMOS and Poseidon exfiltration step: zip the collected folder with ditto, then POST it with curl"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.sophos.com/blog/why-amos-matters-the-macos-malware-stealing-data-at-scale"
        reference_attack = "https://attack.mitre.org/techniques/T1560/001/"
        technique = "T1560.001"
    strings:
        $ditto = /\bditto[ \t]+-c[ \t]+-k\b/ nocase ascii wide
        $upload = /\bcurl\b[^\r\n]{0,256}([ \t](-F|--form)[ \t]+["']?[A-Za-z0-9_-]{1,32}=@|[ \t](--data-binary|-T|--upload-file)[ \t]+["']?@?[\/~$])/ nocase ascii wide
    condition:
        for any i in (1..#ditto) : ($upload in (@ditto[i]..@ditto[i] + 4096))
}
