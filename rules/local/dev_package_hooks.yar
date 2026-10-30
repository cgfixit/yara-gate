rule dev_python_pth_exec {
    meta:
        author = "yara-gate"
        description = "Python .pth file whose import line executes, decodes, or spawns code"
        intent = "Advisory on a .pth file (site-packages runs any line that starts with import at every interpreter start) whose import line calls exec or eval, decodes base64, base85, zlib, or marshal data, starts a process, or opens a URL. The LiteLLM 1.82.7 and 1.82.8 packages shipped this shape. setuptools distutils-precedence, virtualenv, editable-install, and path-only .pth files stay clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1546/018/"
        reference_incident = "https://github.com/BerriAI/litellm/issues/24518"
        technique = "T1546.018"
    strings:
        $line = /(^|\n)import[ \t][^\r\n]{0,8192}\b(exec|eval|compile|b64decode|b85decode|a85decode|decompress|marshal\.loads|subprocess|os\.system|os\.popen|urlopen|urlretrieve)\b/ ascii
    condition:
        yara_gate_ext == "pth" and $line
}
