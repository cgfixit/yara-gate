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
            yara_gate_ext == "svg" or yara_gate_ext == "svgz" or $root at 0 or not yara_gate_svg_scope_proven
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

rule doc_svg_active_link {
    meta:
        author = "yara-gate"
        description = "SVG link or animation whose target is a javascript: URL, or a foreignObject that embeds a frame, object, form, or refresh"
        intent = "Advisory on an SVG that runs or loads something without a script element or an event handler: an a element whose href or xlink:href is a javascript: URL, a set or animate element whose to, from, or values write one, or a foreignObject that holds an iframe, object, embed, form, or meta refresh before it closes. A javascript: target that is empty, a semicolon, or void(0) is the legacy no-op link and stays clean, as do https and fragment links, foreignObject labels written as div, span, or p (diagram exports), and an embedding element after the foreignObject has closed. Scope is the test doc_svg_event_handler uses: outside an SVG document (an svg or svgz name, or an svg root element) the element must sit inside an svg element, and markup the scope proof declines, such as a page with a foreignObject, keeps the strict test. More than 1,024 svg tags or matches keep the strict test"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.w3.org/TR/SVG2/linking.html#AElement"
        reference_research = "https://www.cloudflare.com/cloudforce-one/research/svgs-the-hackers-canvas"
        reference_attack = "https://attack.mitre.org/techniques/T1566/001/"
        technique = "T1566.001"
    strings:
        $svg = /<svg\b/ nocase ascii
        // A link element (optionally namespace-prefixed) and the first and the last href or
        // xlink:href in its tag that holds a javascript: URL. A well-formed tag has at most one
        // of each attribute, so the two ends cover every javascript: target the tag has; the
        // lazy string and the greedy one are separate because YARA-X does not mix them.
        $link_first = /<([A-Za-z][\w.-]{0,32}?:)??a\s([^<>]{0,1024}?\s)??(xlink:)??href\s*?=\s*?["']??\s*?javascript:/ nocase ascii
        $link_last = /<([A-Za-z][\w.-]{0,32}:)?a\s([^<>]{0,1024}\s)?(xlink:)?href\s*=\s*["']?\s*javascript:/ nocase ascii
        // The legacy no-op target, read from the javascript: token itself: nothing, a semicolon,
        // or void(0), then the end of the value. A link whose javascript: starts one of these is
        // clean, which one offset lookup tests; void with any other operand runs it.
        $void = /javascript:(\s*(void(\s*\(\s*0\s*\)|\s+0))?\s*;?\s*["']|(void\(0\))?;?[\s\/>])/ nocase ascii
        // An animation that writes a javascript: value, the scriptless link trigger.
        $animate = /<([A-Za-z][\w.-]{0,32}:)?(set|animate)\s([^<>]{0,1024}\s)?(to|from|values)\s*=\s*["']?[^"'<>]{0,256}javascript:/ nocase ascii
        // A foreignObject opener and the first embedding element after it; whether the
        // foreignObject is still open there is decided in the condition, on offsets.
        $foreign = /<([A-Za-z][\w.-]{0,32}?:)??foreignObject\b[\s\S]{0,4096}?<([A-Za-z][\w.-]{0,32}?:)??(iframe|object|embed|form|meta\s[^<>]{0,256}?http-equiv\s*?=\s*?["']??\s*?refresh)\b/ nocase ascii
        $foreign_close = /<\/([A-Za-z][\w.-]{0,32}:)?foreignObject\s*>/ nocase ascii
        $svg_end = /<\/svg\s*>/ nocase ascii
        $svg_self = /<svg\b[^<>]{0,4096}\/>/ nocase ascii
        $root = /(\xEF\xBB\xBF)?\s*(<\?xml[^<>]{0,512}\?>\s*)?((<!--[^>]{0,4096}-->|<!DOCTYPE[^<>]{0,1024}>)\s*){0,8}<svg\b/ nocase ascii
    condition:
        $svg and (
            (
                yara_gate_ext == "svg" or yara_gate_ext == "svgz" or $root at 0 or not yara_gate_svg_scope_proven
                // As in doc_svg_event_handler, a flood of more than 1,024 matches keeps the strict test.
                or #svg > 1024 or #svg_end > 1024 or #svg_self > 1024
                or #link_first > 1024 or #link_last > 1024 or #animate > 1024 or #foreign > 1024
            ) and (
                $animate
                // A foreignObject match counts while no close lies between its opener and the
                // embedding element; past 1,024 closes every match counts, so a flood cannot
                // make the condition slow.
                or for any i in (1..#foreign) : (
                    #foreign_close > 1024 or #foreign_close in (@foreign[i]..@foreign[i] + !foreign[i]) == 0
                )
                // A link counts unless its javascript: token, the last 11 bytes of the match,
                // starts a no-op target.
                or for any of ($link_first, $link_last) : (
                    for any i in (1..#) : ( not $void at (@[i] + ![i] - 11) )
                )
            )
            // In another document the match must sit inside an svg element: more svg start tags
            // than end tags precede it.
            or for any i in (1..#animate) : (
                #svg in (0..@animate[i]) > #svg_end in (0..@animate[i]) + #svg_self in (0..@animate[i] - 1)
            )
            or for any i in (1..#foreign) : (
                #svg in (0..@foreign[i]) > #svg_end in (0..@foreign[i]) + #svg_self in (0..@foreign[i] - 1)
                and (#foreign_close > 1024 or #foreign_close in (@foreign[i]..@foreign[i] + !foreign[i]) == 0)
            )
            or for any of ($link_first, $link_last) : (
                for any i in (1..#) : (
                    #svg in (0..@[i]) > #svg_end in (0..@[i]) + #svg_self in (0..@[i] - 1)
                    and not $void at (@[i] + ![i] - 11)
                )
            )
        )
}
