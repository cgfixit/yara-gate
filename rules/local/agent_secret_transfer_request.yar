rule agent_secret_transfer_request {
    meta:
        author = "yara-gate"
        description = "Request to read sensitive material and transfer it to an outbound destination"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $request = /\b(read|collect|extract|copy)[\s\S]{0,96}(\.env|private key|credentials|conversation history|system prompt)[\s\S]{0,128}(send|upload|post|transmit)[\s\S]{0,128}(https?:\/\/|webhook|remote server)/ nocase ascii wide
    condition:
        $request
}
