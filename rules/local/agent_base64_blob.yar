rule agent_base64_blob {
    meta:
        author = "yara-gate"
        description = "A base64 run of 400 or more characters, independent of filename"
        intent = "Advisory on a long base64 run that is not a PEM block or an SSH public key"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://datatracker.ietf.org/doc/html/rfc4648"
    strings:
        $b = /[A-Za-z0-9+\/]{400}={0,2}/
        $pem = /-----BEGIN [A-Z0-9 ]{1,40}-----[\r\n]+[A-Za-z0-9+\/]{400}={0,2}/
        $ssh = /\bssh-(rsa|ed25519)[ \t]+[A-Za-z0-9+\/]{400}={0,2}/
    condition:
        $b and not $pem and not $ssh
}
