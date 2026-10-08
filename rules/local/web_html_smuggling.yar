rule web_html_smuggling {
    meta:
        author = "yara-gate"
        description = "Base64 decoding and Blob URL creation near a script, executable, disk image or archive download"
        verdict_on_match = "advisory"
        reference = "https://www.microsoft.com/en-us/security/blog/2021/11/11/html-smuggling-surges-highly-evasive-loader-technique-increasingly-used-in-banking-malware-targeted-attacks/"
    strings:
        $decode = /\batob[ \t\r\n]*\(/ ascii wide
        $blob = /\bnew[ \t\r\n]+Blob[ \t\r\n]*\(/ ascii wide
        $url = /\b(URL|webkitURL)[ \t]*\.[ \t]*createObjectURL[ \t\r\n]*\(/ ascii wide
        $download = /(\.download[ \t]*=[ \t]*|\.setAttribute\([ \t]*["']download["'][ \t]*,[ \t]*)["'][^"'\r\n]{1,120}\.(exe|dll|js|jse|vbs|vbe|wsf|hta|lnk|iso|img|vhd|vhdx|zip|7z)["']/ nocase ascii wide
    condition:
        for any i in (1..#download) : (
            $decode in (@download[i] - 4096..@download[i] + 4096) and
            $blob in (@download[i] - 4096..@download[i] + 4096) and
            $url in (@download[i] - 4096..@download[i] + 4096)
        )
}
