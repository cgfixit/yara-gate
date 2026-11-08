rule doc_svg_active {
    meta:
        id = "doc_svg_active"
        author = "yara-gate"
        description = "SVG script, onload handler, or foreignObject with a script"
        intent = "Block an SVG that contains a script or an onload handler. In an SVG document (an svg or svgz name, or an svg root element) any script or onload blocks. In other text, such as an HTML page with an inline icon, the script or handler must sit inside an svg element: more svg start tags than end tags precede it, or it is on the svg start tag itself. A page script or body onload beside a scriptless svg is not matched. More than 1,024 svg tags, scripts, or onload handlers keep the strict test"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://attack.mitre.org/techniques/T1204/"
    strings:
        $svg = /<svg\b/ nocase ascii
        $script = /<script\b/ nocase ascii
        $onload = /onload\s*=/ nocase ascii
        $foreign = /<foreignObject\b/ nocase ascii
        // An svg end tag, and a self-closing svg start tag, which has no content.
        $svg_end = /<\/svg\s*>/ nocase ascii
        $svg_self = /<svg\b[^<>]{0,4096}\/>/ nocase ascii
        // An onload on the svg start tag itself, self-closing or not.
        $svg_onload = /<svg\b[^<>]{0,4096}onload\s*=/ nocase ascii
        // The document's root element is svg: an optional byte order mark, XML declaration,
        // comments, doctype, and whitespace before it.
        $root = /(\xEF\xBB\xBF)?\s*(<\?xml[^<>]{0,512}\?>\s*)?((<!--[^>]{0,4096}-->|<!DOCTYPE[^<>]{0,1024}>)\s*){0,8}<svg\b/ nocase ascii
    condition:
        $svg and ($script or $onload or ($foreign and $script)) and (
            yara_gate_ext == "svg" or yara_gate_ext == "svgz" or $root at 0 or not yara_gate_svg_scope_proven or $svg_onload
            // Each scope test counts every svg tag before a match, so more than 1,024 matches
            // of any of these patterns keeps the strict test: a flood can hide no script and
            // cannot make the condition quadratic.
            or #svg > 1024 or #svg_end > 1024 or #svg_self > 1024 or #script > 1024 or #onload > 1024
            or for any i in (1..#script): (
                #svg in (0..@script[i]) > #svg_end in (0..@script[i]) + #svg_self in (0..@script[i])
            )
            or for any i in (1..#onload): (
                #svg in (0..@onload[i]) > #svg_end in (0..@onload[i]) + #svg_self in (0..@onload[i])
            )
        )
}
