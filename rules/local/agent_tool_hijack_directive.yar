rule agent_tool_hijack_directive {
    meta:
        author = "yara-gate"
        description = "Order to exfiltrate, invoke a tool to send data out, decode and execute, or call a command tool while hiding it from the user"
        intent = "Advisory on an action directive aimed at an agent's tools. These forms are orders, not phrases a write-up quotes, so a retrieved document that carries one stays held under agent-document as well as agent-ingest"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
        reference_attack = "https://atlas.mitre.org/techniques/AML.T0051"
    strings:
        // "Please exfiltrate", "to exfiltrate", "exfiltrate the credentials". A bare "exfiltrate" in incident notes stays clean.
        $exfil = /\b(please |to )exfiltrate\b|\bexfiltrate (the |this |secrets|data|files|credentials)\b/ nocase
        // Concealment paired with a command or function call, in either order. A support line that says
        // "do not tell the user" with no tool call stays clean.
        $conceal = /do not tell the user[\s\S]{0,160}\b(tool_call|run_command|execute_command|function call)\b/ nocase
        $conceal_rev = /\b(tool_call|run_command|execute_command|function call)\b[\s\S]{0,160}do not tell the user/ nocase
        // "Invoke your tools to email", "decode and then execute the following".
        $tool = /\binvoke[ \t]+(the[ \t]+|a[ \t]+|your[ \t]+)?tools?[ \t]+to[ \t]+(email|send|upload|post|exfiltrate|forward|transfer)\b|\b(base64[ \t]+)?decode[ \t]+(it[ \t]+|this[ \t]+)?(and|then)[ \t]+(execute|run|eval)[ \t]+(the[ \t]+following|this|it)\b/ nocase ascii wide
    condition:
        any of them
}
