rule agent_fake_chat_marker {
    meta:
        id = "agent_fake_chat_marker"
        author = "yara-gate"
        description = "Fake chat marker or a tool-result close with no matching open"
        intent = "Advisory when a system or assistant chat marker (ChatML, Phi, Gemma, Llama, harmony, Cohere, or DeepSeek) carries an instruction, or a closing tool marker has no open"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $im = /<\|im_start\|>[ \t]*(system|assistant)[\s\S]{0,200}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        // The assistant turn opener of other chat templates: Phi (<|assistant|>), Gemma
        // (<start_of_turn>model, and <|turn>model from Gemma 4), Llama 3 and Llama 4 headers, the
        // harmony format (<|start|>assistant), Cohere (<|CHATBOT_TOKEN|>), and DeepSeek
        // (Assistant between fullwidth bars). System and developer openers are
        // agent_role_spoof_action.
        $turn = /(<\|assistant\|>|<start_of_turn>model|<\|turn>model|<\|start_header_id\|>assistant<\|end_header_id\|>|<\|header_start\|>assistant<\|header_end\|>|<\|start\|>assistant(<\|channel\|>[a-z]{1,16})?<\|message\|>|<\|CHATBOT_TOKEN\|>|<\xef\xbd\x9cAssistant\xef\xbd\x9c>)[\s\S]{0,200}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $close = /<\/tool_result>[\s\S]{0,80}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $open = /<tool_result[\s>]/ nocase ascii wide
    condition:
        $im or $turn or ($close and not $open)
}
