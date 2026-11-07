rule doc_svg_event_handler {
    meta:
        id = "doc_svg_event_handler"
        author = "yara-gate"
        description = "SVG animation onbegin or image onerror handler with a body"
        intent = "Advisory when an SVG animation element carries a non-empty onbegin handler, or an SVG image, feImage, svg, or use element carries a non-empty onerror handler. Event presence is an active-content indicator, not proof of malware: whether it runs depends on how the SVG is embedded. Script and onload stay with doc_svg_active, which blocks. HTML img onerror, an empty handler, a data-onbegin attribute, and prose naming the attribute are not matched. Outside an SVG document (an svg or svgz name, or an svg root element), the element must sit inside an svg element or be the svg start tag: an HTML parser reads an image tag outside svg as img. More than 1,024 svg tags or handlers keep the strict test"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.w3.org/TR/SVG2/interact.html#EventAttributes"
    strings:
        $svg = /<svg\b/ nocase ascii
        // The element name (optionally namespace-prefixed), its other attributes within the same tag,
        // then the handler with a first non-space character, quoted or not; spaces after the quote
        // are allowed, so only an empty or all-space handler is clean.
        $begin = /<([A-Za-z][\w.-]{0,32}:)?(animate|animateMotion|animateTransform|animateColor|set)\b[^<>]{0,1024}\sonbegin\s*=\s*(["']\s*)?[^\s"'>]/ nocase ascii
        $error = /<([A-Za-z][\w.-]{0,32}:)?(image|feImage|svg|use)\b[^<>]{0,1024}\sonerror\s*=\s*(["']\s*)?[^\s"'>]/ nocase ascii
        // The same scope test as doc_svg_active: svg end tags and self-closing svg start tags.
        // A self-closing tag counts as closed only when it starts before the handler's element.
        $svg_end = /<\/svg\s*>/ nocase ascii
        $svg_self = /<svg\b[^<>]{0,4096}\/>/ nocase ascii
        $root = /(\xEF\xBB\xBF)?\s*(<\?xml[^<>]{0,512}\?>\s*)?((<!--[^>]{0,4096}-->|<!DOCTYPE[^<>]{0,1024}>)\s*){0,8}<svg\b/ nocase ascii
    condition:
        $svg and ($begin or $error) and (
            yara_gate_ext == "svg" or yara_gate_ext == "svgz" or $root at 0
            // As in doc_svg_active, a flood of more than 1,024 matches keeps the strict test.
            or #svg > 1024 or #svg_end > 1024 or #svg_self > 1024 or #begin > 1024 or #error > 1024
            or for any i in (1..#begin): (
                #svg in (0..@begin[i]) > #svg_end in (0..@begin[i]) + #svg_self in (0..@begin[i] - 1)
            )
            or for any i in (1..#error): (
                #svg in (0..@error[i]) > #svg_end in (0..@error[i]) + #svg_self in (0..@error[i] - 1)
            )
        )
}
