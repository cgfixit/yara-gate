rule win_browser_credential_decrypt {
    meta:
        author = "yara-gate"
        description = "Script or source that reads Chromium's saved-password store and its Local State key, and decrypts with DPAPI"
        intent = "Advisory on the infostealer core: the Login Data database, the encrypted_key or app_bound_encrypted_key from Local State, and CryptUnprotectData or ProtectedData.Unprotect in one file. A path list alone, as in a sandbox deny-list, a cleaner, or a threat report, stays clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1555/003/"
        technique = "T1555.003"
    strings:
        $store = "Login Data" nocase ascii wide
        $key = /\b(app_bound_)?encrypted_key\b/ ascii wide
        $dpapi = /\b(CryptUnprotectData|ProtectedData\]?(::|\.)Unprotect)\b/ nocase ascii wide
    condition:
        $store and $key and $dpapi
}

rule macos_stealer_password_check {
    meta:
        author = "yara-gate"
        description = "dscl authonly password check in the same file as browser, cookie, or wallet stores"
        intent = "Advisory on the AMOS and Banshee shape: the script checks the password it prompted for with dscl . -authonly, and the same file names browser credential databases, Safari cookies, Firefox key4.db or logins.json, or wallet applications to collect. Administration scripts that test a password, as in LAPS tools, stay clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.elastic.co/security-labs/beyond-the-wail"
        reference_attack = "https://attack.mitre.org/techniques/T1555/001/"
        technique = "T1555.001"
    strings:
        $authonly = /\bdscl[ \t]+(\.|\/Local\/Default)[ \t]+-?authonly\b/ nocase ascii wide
        $store = /Login Data|Cookies\.binarycookies|key4\.db|logins\.json|\bExodus\b|\bElectrum\b|\bMetaMask\b|nkbihfbeogaeaoehlefnkodbefgpgknn|\bAtomic Wallet\b|\bCoinomi\b/ nocase ascii wide
    condition:
        $authonly and $store
}
