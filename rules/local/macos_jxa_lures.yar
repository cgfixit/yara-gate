rule macos_jxa_remote_exec {
    meta:
        author = "yara-gate"
        description = "JavaScript for Automation that evaluates code fetched from a URL, or runs a downloader through doShellScript"
        intent = "Advisory on osascript -l JavaScript, ObjC.import, or Application.currentApplication() in a file that also loads a URL into memory and calls eval, or passes curl, wget, a base64 decode, or chmod +x to doShellScript. A JXA automation that drives an application or runs a local command stays clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/007/"
        technique = "T1059.007"
    strings:
        $jxa = /\bosascript\b[^\r\n]{0,40}-l[ \t]+JavaScript\b|\bObjC\.import[ \t]*\(|\bApplication\.currentApplication[ \t]*\(\)/ ascii wide
        $url = /\b(dataWithContentsOfURL|stringWithContentsOfURL|NSURL\.URLWithString)\b/ ascii wide
        $eval = /\beval[ \t]*\(/ ascii wide
        $shell = /\bdoShellScript[ \t]*\([ \t]*["'`][^"'`\r\n]{0,256}\b(curl|wget|base64[ \t]+(-d|-D|--decode)|chmod[ \t]+\+x)\b/ ascii wide
    condition:
        $jxa and (($url and $eval) or $shell)
}
