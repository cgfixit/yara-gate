rule doc_svg_active {
    meta:
        id = "doc_svg_active"
        author = "yara-gate"
        description = "SVG script, onload handler, or foreignObject with a script"
        intent = "Block an SVG that contains a script or an onload handler"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://attack.mitre.org/techniques/T1204/"
    strings:
        $svg = /<svg\b/ nocase ascii
        $script = /<script\b/ nocase ascii
        $onload = /onload\s*=/ nocase ascii
        $foreign = /<foreignObject\b/ nocase ascii
    condition:
        $svg and ($script or $onload or ($foreign and $script))
}
