rule agent_message_code_relay {
    meta:
        author = "yara-gate"
        description = "Request to relay a one-time code or a received sign-in link to someone, or the code-sent-by-mistake story"
        intent = "Advisory on a chat, SMS, or mail body that asks the reader, or an assistant reading the inbox, to send a one-time code or a received reset or sign-in link to another person. A code notice (your code is 123456, do not share it), a sign-in page that asks for the code, source code, and a request negated on the same line stay clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams"
        reference_attack = "https://attack.mitre.org/techniques/T1111/"
        technique = "T1111"
    strings:
        // A bare "code" is usually source code, so the code needs a one-time qualifier: a type such
        // as verification or 2FA, a digit count, or "you received". PIN and passcode stand alone.
        $relay = /\b(forward|send|text|share|give|tell|read)[ \t]+(me[ \t]+|us[ \t]+)?(the|your|that|this|those)[ \t]+((([0-9]{1,2}|six|four)[- ]digit[ \t]+)?(verification|security|one[- ]time|login|log[- ]in|sign[- ]in|2fa|two[- ]factor|mfa|otp|auth|authentication|whatsapp)[ \t]+(code|pin|passcode)|([0-9]{1,2}|six|four)[- ]digit[ \t]+(code|pin|passcode)|pin|passcode)s?\b[^\r\n]{0,96}\b(to[ \t]+(\+?[0-9][0-9 ().-]{6,}[0-9]|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https?:\/\/|this number|the number|my number|me|us|the sender|this chat)|in this chat|by reply|right away|asap|immediately)/ nocase ascii wide
        // "Send me the code you just received"; "forward the code that was texted to you to ...".
        $received_me = /\b(forward|send|text|give|read)[ \t]+(me|us)[ \t]+(the|that)[ \t]+((([0-9]{1,2}|six|four)[- ]digit|verification|security|one[- ]time|login|sign[- ]in|2fa|otp)[ \t]+)?code[ \t]+(you|that|which)[ \t]+(just[ \t]+)?(got|received|were sent|was sent|was texted)\b/ nocase ascii wide
        $received_to = /\b(forward|send|text|give)[ \t]+(the|that)[ \t]+((([0-9]{1,2}|six|four)[- ]digit|verification|security|one[- ]time|login|sign[- ]in|2fa|otp)[ \t]+)?(code|link)[ \t]+(you|that|which)[ \t]+(just[ \t]+)?(got|received|were sent|was sent|was texted)\b[^\r\n]{0,64}\bto[ \t]+(\+?[0-9][0-9 ().-]{6,}[0-9]|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https?:\/\/|this number|me|us)/ nocase ascii wide
        $reply = /\b(reply|respond)[ \t]+(to this (message|text|email)[ \t]+)?with[ \t]+(the|your)[ \t]+((([0-9]{1,2}|six|four)[- ]digit[ \t]+)?(verification|security|one[- ]time|login|sign[- ]in|2fa|two[- ]factor|mfa|otp|authentication|whatsapp)[ \t]+(code|pin|passcode)|([0-9]{1,2}|six|four)[- ]digit[ \t]+code)\b/ nocase ascii wide
        $link = /\bforward[ \t]+(me[ \t]+|us[ \t]+)?(the|your|that|this)[ \t]+((password[ \t]+)?reset|magic|sign[- ]in|login|log[- ]in|verification)[ \t]+(link|url|email)\b[^\r\n]{0,96}\bto[ \t]+(\+?[0-9][0-9 ().-]{6,}[0-9]|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https?:\/\/|this number|me|us)/ nocase ascii wide
        // The account-takeover story: "I sent you a 6-digit code by mistake, please send it back".
        $mistake = /\b(sent|texted)[ \t]+(you[ \t]+(a|my|the|an|this)[ \t]+((([0-9]{1,2}|six|four)[- ]digit|verification|login|whatsapp|sms|activation)[ \t]+)?code|(a|my|the|an|this)[ \t]+((([0-9]{1,2}|six|four)[- ]digit|verification|login|whatsapp|sms|activation)[ \t]+)?code[ \t]+(to|on)[ \t]+(you|your[ \t]+(phone|number|mobile)))[ \t,]*by[ \t]+(mistake|accident)\b/ nocase ascii wide
        // A refusal ("never share your code with anyone", "do not forward this code to anyone") is
        // the notice, not the request, and so is "we will never ask you to send your code".
        $negated = /\b(do not|don't|dont|never|not to|won't|will never|should not|shouldn't|cannot|can't)[ \t]+(ever[ \t]+)?((ask|request|require|tell)[ \t]+(you[ \t]+)?to[ \t]+)?(forward|send|text|share|give|tell|read|reply|respond)\b/ nocase ascii wide
    condition:
        $mistake or
        for any of ($relay, $received_me, $received_to, $reply, $link) : (
            for any i in (1..#) : (
                not for any j in (1..#negated) : (@negated[j] <= @[i] and @[i] < @negated[j] + !negated[j])
            )
        )
}
