rule win_rdp_resource_redirect {
    meta:
        author = "yara-gate"
        description = "Remote Desktop connection file that redirects local drives or opens a RemoteApp on a named host"
        intent = "Advisory on an .rdp file whose full address is set and that redirects drives (drivestoredirect with a value) or enables RemoteApp mode, the rogue-RDP lure shape"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties"
        reference_campaign = "https://cloud.google.com/blog/topics/threat-intelligence/windows-rogue-remote-desktop-protocol"
        technique = "T1021.001"
    strings:
        // mstsc saves drivestoredirect:s: with an empty value; a value (*, DynamicDrives, or
        // drive letters) maps the local disks into the session. remoteapplicationmode:i:1 shows
        // the server's program instead of a desktop. The address is what makes it a connection.
        $addr = /\b(alternate )?full address:s:[^\r\n \t]/ nocase ascii wide
        $drives = /(^|[\r\n])[ \t]*drivestoredirect:s:[ \t]*[^\r\n \t]/ nocase ascii wide
        $remoteapp = /(^|[\r\n])[ \t]*remoteapplicationmode:i:1\b/ nocase ascii wide
    condition:
        $addr and ($drives or $remoteapp)
}

rule win_theme_remote_resource {
    meta:
        author = "yara-gate"
        description = "Windows theme whose wallpaper, brand image, or visual style loads from a UNC path or file URL"
        intent = "Advisory on a .theme file that makes the host fetch a resource from a remote share when the theme is shown or applied"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://learn.microsoft.com/en-us/windows/win32/controls/themesfileformat-overview"
        reference_research = "https://www.akamai.com/blog/security-research/leaking-ntlm-credentials-through-windows-themes"
        technique = "T1187"
    strings:
        // The file must carry a theme section; the same keys in another INI are not a theme.
        $section = /(^|[\r\n])[ \t]*\[(Theme|Control Panel\\Desktop|VisualStyles)\]/ nocase ascii wide
        $image = /(^|[\r\n])[ \t]*(BrandImage|Wallpaper)[ \t]*=[ \t]*["']?(\\\\[^\\\r\n]|file:)/ nocase ascii wide
        // The [VisualStyles] header and a remote Path line that starts within 512 bytes after it
        // are two strings paired in the condition. One pattern with [\s\S]{0,512} between them is
        // split by YARA-X at a gap over 200 bytes and paired match by match, which reached the
        // scan deadline on a file of them (docs/verification/2026-11-20-any-byte-gap-timing.md).
        // The ascii and wide copies are separate so a UTF-16 header is paired only with a UTF-16
        // line; the window is 512 bytes for both, as [\s\S] matches one byte in a wide pattern.
        $styles = /\[VisualStyles\]/ nocase ascii
        $styles_wide = /\[VisualStyles\]/ nocase wide
        $path = /[\r\n][ \t]*Path[ \t]*=[ \t]*["']?(\\\\[^\\\r\n]|file:)/ nocase ascii
        $path_wide = /[\r\n][ \t]*Path[ \t]*=[ \t]*["']?(\\\\[^\\\r\n]|file:)/ nocase wide
    condition:
        $section and (
            $image
            or for any i in (1..#styles) : ( $path in (@styles[i] + !styles[i]..@styles[i] + !styles[i] + 512) )
            or for any i in (1..#styles_wide) : (
                $path_wide in (@styles_wide[i] + !styles_wide[i]..@styles_wide[i] + !styles_wide[i] + 512)
            )
            // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
            // notice. A full list of a header or a Path line counts as a header with its line,
            // so a flood ahead of a pair cannot hide it
            // (docs/verification/2026-11-17-match-cap-rules.md).
            or (
                (#styles >= 1000000 or #styles_wide >= 1000000 or #path >= 1000000 or #path_wide >= 1000000)
                and ($styles or $styles_wide) and ($path or $path_wide)
            )
        )
}
