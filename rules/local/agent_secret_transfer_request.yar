rule agent_secret_transfer_request {
    meta:
        author = "yara-gate"
        description = "Request to read sensitive material and transfer it to an outbound destination, or a one-line request to send the prompt, hidden instructions, memory file, or your credentials"
        intent = "Advisory on a request to read a secret and send it"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $request = /\b(read|collect|extract|copy)[\s\S]{0,96}(\.env|private key|credentials|conversation history|system prompt)[\s\S]{0,128}(send|upload|post|transmit)[\s\S]{0,128}(https?:\/\/|webhook|remote server)/ nocase ascii wide
        // A one-line request to hand over the prompt, hidden instructions, or memory file to anyone, or
        // your own credentials; the destination is optional because the request itself is the signal.
        $short = /\b(send|post|forward|text|email|paste|reply with)[ \t]+(me[ \t]+)?((your|the|its)[ \t]+(full[ \t]+)?(contents?[ \t]+of[ \t]+(your|the|its)[ \t]+)?(system prompt|hidden instructions|initial instructions|memory file)|your[ \t]+(credentials|api key|password|secret key))\b/ nocase ascii wide
    condition:
        $request or $short
}
