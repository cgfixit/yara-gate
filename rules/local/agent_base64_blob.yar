rule agent_base64_blob {
    meta:
        author = "yara-gate"
        description = "A base64 run of 400 or more characters, independent of filename, that is not media, a font, a PEM body, or an SSH key"
        intent = "Advisory on a long base64 run whose own start is not an image, audio, video, or font header and does not follow a data: media URI, a PEM header, or an SSH key type"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://datatracker.ietf.org/doc/html/rfc4648"
    strings:
        // Each match starts on the byte before a run (or at offset 0), so @b[i] + 1 is the run's
        // first character and an exemption applies to that run only, not to the whole file.
        $b = /(^|[^A-Za-z0-9+\/])[A-Za-z0-9+\/]{400}/
        // PNG, JPEG, GIF, WebP, ISO-BMFF (AVIF, HEIC, MP4), MP3, Ogg, WOFF, WOFF2, OpenType, TrueType:
        // only the characters the magic bytes fix, since the next one depends on the following byte.
        $media = /(^|[^A-Za-z0-9+\/])(iVBORw0KGg|\/9j\/|R0lGOD[dl]h|UklGR[A-Za-z0-9+\/]{7}RUJQ|AAAA[A-Za-z0-9+\/]{2}Z0eX|SUQz|T2dnU|d09GR|d09GM|T1RUT|AAEAAA)/
        $prefix = /data:(image|audio|video|font)\/[A-Za-z0-9.+-]{1,64};base64,|-----BEGIN [A-Z0-9 ]{1,40}-----[\r\n]+|\b(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521))[ \t]+/
    condition:
        for any i in (1..#b) : (
            not $media at @b[i] and
            not for any j in (1..#prefix) : (@prefix[j] + !prefix[j] == @b[i] + 1)
        )
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
    strings:
        // MZ encodes as TV followed by o, p, q, or r; 7F 45 4C 46 as f0VMR; FE ED FA CE/CF as /u36z;
        // the little-endian CE/CF FA ED FE as zvrt/ or z/rt/. CA FE BA BE is left out because Java
        // class files share it with fat Mach-O. Each suffix length makes the whole run 400.
        $exe = /(^|[^A-Za-z0-9+\/])(TV[opqr][A-Za-z0-9+\/]{397}|(f0VMR|\/u36z|z[v\/]rt\/)[A-Za-z0-9+\/]{395})/
    condition:
        $exe
}
