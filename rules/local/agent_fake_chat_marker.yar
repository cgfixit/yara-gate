rule agent_fake_chat_marker {
    meta:
        id = "agent_fake_chat_marker"
        author = "yara-gate"
        description = "Fake chat marker or a tool-result close with no matching open"
        intent = "Advisory when a system or assistant chat marker (ChatML, Phi, Gemma, Llama, harmony, Cohere, DeepSeek, Granite, Kimi, MiniMax, or Inkling) carries an instruction, or a closing tool marker has no open"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $im = /<\|im_start\|>[ \t]*(system|assistant)[\s\S]{0,200}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        // The assistant turn opener of other chat templates: Phi (<|assistant|>), Gemma
        // (<start_of_turn>model, and <|turn>model from Gemma 4), Llama 3 and Llama 4 headers, the
        // harmony format (<|start|>assistant), Cohere (<|CHATBOT_TOKEN|>), DeepSeek
        // (Assistant between fullwidth bars), Granite (<|start_of_role|>assistant), Kimi
        // (<|im_assistant|>assistant<|im_middle|>), MiniMax (]~b]ai), and Inkling
        // (<|message_model|><|content_text|>). System and developer openers are
        // agent_role_spoof_action.
        $turn = /(<\|assistant\|>|<start_of_turn>model|<\|turn>model|<\|start_header_id\|>assistant<\|end_header_id\|>|<\|header_start\|>assistant<\|header_end\|>|<\|start\|>assistant(<\|channel\|>[a-z]{1,16})?<\|message\|>|<\|CHATBOT_TOKEN\|>|<\xef\xbd\x9cAssistant\xef\xbd\x9c>|<\|start_of_role\|>assistant<\|end_of_role\|>|<\|im_assistant\|>assistant<\|im_middle\|>|\]~b\]ai\b|<\|message_model\|><\|content_text\|>)[\s\S]{0,200}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $close = /<\/tool_result>[\s\S]{0,80}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $open = /<tool_result[\s>]/ nocase ascii wide
        // The tool-output wrapper of the Qwen, GLM, and Granite templates. It is paired
        // with its own open tag, so a file that opens one wrapper and closes the other is read
        // as it was.
        $close_response = /<\/tool_response>[\s\S]{0,80}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $open_response = /<tool_response[\s>]/ nocase ascii wide
    condition:
        $im or $turn or ($close and not $open) or ($close_response and not $open_response)
}
