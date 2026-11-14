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

rule dev_gyp_command_expansion {
    meta:
        author = "yara-gate"
        description = "GYP command expansion in a binding.gyp that throws its output away or echoes a stub source name"
        intent = "Advisory on a binding.gyp, .gyp, or .gypi whose <!( or <!@( command expansion sends its output to /dev/null or ends by echoing a C or C++ file name. npm runs node-gyp rebuild for a package with a root binding.gyp and no install script, and GYP runs every expansion as a shell command while it configures, so this runs a script at install with no lifecycle script in package.json. The Miasma wave wrote \"<!(node index.js > /dev/null 2>&1 && echo stub.c)\". The forms native addons use stay clean: node -p or node -e lookups such as require('node-addon-api').include_dir, pkg-config and curl-config, a node -p test that uses && inside JavaScript, and 2>&1 piped to another command"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://gyp.gsrc.io/docs/InputFormatReference.md#command-expansions"
        reference_incident = "https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/"
        reference_osv = "https://osv.dev/vulnerability/MAL-2026-6526"
        technique = "T1195.002"
    strings:
        // binding.gyp has the suffix gyp. Both strings stay inside one line, so a later key on
        // another line is never read as the command.
        $discard = /<!@?\([^\r\n]{0,240}>[ \t]*\/dev\/null\b/ ascii
        $stub = /<!@?\([^\r\n]{0,240}(&&|\|\||;)[ \t]*echo[ \t]+["']?[A-Za-z0-9_.\/-]{1,64}\.(c|cc|cpp|cxx)\b/ ascii
    condition:
        (yara_gate_ext == "gyp" or yara_gate_ext == "gypi") and any of them
}
