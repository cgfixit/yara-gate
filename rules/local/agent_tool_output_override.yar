rule agent_tool_output_override {
    meta:
        author = "yara-gate"
        description = "Tool-result text requesting a command tool to bypass controls"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html"
    strings:
        // Stay inside the textual result; prose after its closing tag is unrelated.
        $call = /<(tool_result|tool_response)>[^<]{0,160}\b(call|invoke|run|execute)[ \t]+(run_command|execute_command|shell|terminal)\b[^<]{0,96}\b(disable|bypass|skip)[ \t]+(user[ \t]+)?(audit logging|safety checks|approval|confirmation)\b/ nocase ascii wide
    condition:
        $call
}
