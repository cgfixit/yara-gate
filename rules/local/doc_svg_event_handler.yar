rule doc_svg_event_handler {
    meta:
        id = "doc_svg_event_handler"
        author = "yara-gate"
        description = "SVG animation onbegin or image onerror handler with a body"
        intent = "Advisory when an SVG animation element carries a non-empty onbegin handler, or an SVG image, feImage, svg, or use element carries a non-empty onerror handler. Event presence is an active-content indicator, not proof of malware: whether it runs depends on how the SVG is embedded. Script and onload stay with doc_svg_active, which blocks. HTML img onerror, an empty handler, a data-onbegin attribute, and prose naming the attribute are not matched"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.w3.org/TR/SVG2/interact.html#EventAttributes"
    strings:
        $svg = /<svg\b/ nocase ascii
        // The element name (optionally namespace-prefixed), its other attributes within the same tag,
        // then the handler with a first non-space character, quoted or not.
        $begin = /<([A-Za-z][\w.-]{0,32}:)?(animate|animateMotion|animateTransform|animateColor|set)\b[^<>]{0,1024}\sonbegin\s*=\s*["']?[^\s"'>]/ nocase ascii
        $error = /<([A-Za-z][\w.-]{0,32}:)?(image|feImage|svg|use)\b[^<>]{0,1024}\sonerror\s*=\s*["']?[^\s"'>]/ nocase ascii
    condition:
        $svg and ($begin or $error)
}
