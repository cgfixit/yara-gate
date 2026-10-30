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
        $style = /\[VisualStyles\][\s\S]{0,512}[\r\n][ \t]*Path[ \t]*=[ \t]*["']?(\\\\[^\\\r\n]|file:)/ nocase ascii wide
    condition:
        $section and ($image or $style)
}
