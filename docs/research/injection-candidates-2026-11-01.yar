// Research-only candidate shapes measured in injection-coverage-expansion-2026-11-01.md.
// NOT shipped and NOT loaded: the scanner reads rules/local only. These carry no verdict_on_match.
// They were written from the threat model (fake turns, boundary spoofing, tool directives,
// concealment, task overrides), not from corpus literals, then measured once. Any promotion needs
// fire/near-miss pairs, the precision corpus, and a severity decision (see the note).

rule cand_turn_marker_extended {
    strings:
        $inst = /\[\/?INST\]|<<\/?SYS>>/
        $special = /<\|(start|end|message|channel|system|user|assistant|eot_id|begin_of_text|start_header_id|end_header_id|endoftext)\|>/ nocase
        $gemma = /<(start|end)_of_turn>/
        $tag = /<\/?(user|assistant|system|human)(_(message|query|input|turn|prompt))?>/ nocase
        $begin = /\b(begin|end|start)[ \t_-]+(of[ \t_-]+)?(the[ \t_-]+)?(user|assistant|system)[ \t_-]+(message|turn|prompt|input|instructions?|query)\b/ nocase
        $piped = /<\|{1,2}[ \t]*(user|assistant|system)[ \t]*\|{1,2}>/ nocase
    condition:
        any of them
}

rule cand_context_boundary_spoof {
    strings:
        $close = /<\/(email|emails|context|document|documents|untrusted[_-]?(data|content|input|text)?|retrieved[_-]?(content|context|data)|search[_-]?results?|tool[_-]?(output|result|response)s?|function[_-]?results?|external[_-]?(content|data))>/ nocase
        $end = /\b(end|close)[ \t]+of[ \t]+(the[ \t]+)?(email|message|document|context|data|input|user[ \t]+(input|query|data))\b[^\n]{0,12}[\r\n]{1,4}[^\n]{0,80}\b(you|assistant|ai|now|please|must|ignore|new)\b/ nocase
    condition:
        any of them
}

rule cand_send_to_address_with_content {
    strings:
        $s = /\b(send|forward|e-?mail|reply|respond|write)\b[^\n]{0,60}\bto\b[^\n]{0,15}[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63}){0,4}\.[A-Za-z]{2,24}[^\n]{0,60}\b(with|containing|saying|stating)\b[^\n]{0,20}\b(the[ \t]+)?(body|subject|text|content|word|message|phrase)\b/ nocase
    condition:
        $s
}

rule cand_tool_call_directive {
    strings:
        $named = /\b(call|invoke|use|trigger|execute|run)[ \t]+(the[ \t]+|a[ \t]+|your[ \t]+)?[`'"]?[a-z][a-z0-9]*(_[a-z0-9]+)+[`'"]?[ \t]+(tool|function|api|action)\b/ nocase
        $generic = /\b(call|invoke|use|trigger|execute|run)[ \t]+(the[ \t]+|your[ \t]+)?(email|e-mail|mail|messaging|sending|send|api|browser|shell|file|http)[ \t]+(tool|function|api|plugin|capability)\b/ nocase
    condition:
        any of them
}

rule cand_concealed_action {
    strings:
        $hide = /\b((do[ \t]+not|don't|never)[ \t]+(tell|mention|inform|reveal|show|alert|notify|disclose)[ \t]+(this[ \t]+|it[ \t]+|that[ \t]+|anything[ \t]+)?(to[ \t]+)?the[ \t]+(user|human|recipient|operator)|without[ \t]+(telling|informing|notifying|alerting|asking)[ \t]+the[ \t]+(user|human|recipient|operator))\b/ nocase
        $target = /https?:\/\/|[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,24}|~\/\.ssh|\bid_(rsa|ed25519)\b|\.env\b|\bapi[ _-]?key\b|\b(send|forward|upload|post|attach|include)[ \t]+(it|this|them|the[ \t]+\w+)[ \t]+to\b/ nocase
        $silent = /\b(silently|secretly|quietly|covertly)[ \t]+(send|forward|add|include|run|execute|call|upload|insert|append|email|copy)\b/ nocase
    condition:
        $silent or for any i in (1..#hide) : (
            for any j in (1..#target) : (@target[j] > @hide[i] - 300 and @target[j] < @hide[i] + 300)
        )
}

rule cand_task_override {
    strings:
        $n1 = /\byour[ \t]+(new|real|actual|true|updated|primary|only|next)[ \t]+(task|instructions?|goal|objective|job|mission|priority)[ \t]+(is|are|will[ \t]+be)\b/ nocase
        $n2 = /\b(new|updated|additional|hidden|secret|urgent)[ \t]+(task|instructions?|objective|directive)s?[ \t]*(for[ \t]+you)?[ \t]*:/ nocase
        $n3 = /\bbefore[ \t]+(you[ \t]+)?(summari[sz]ing|summari[sz]e|answering|answer|responding|respond|replying|reply)\b[^\n]{0,60}\b(you[ \t]+must|please|first|make[ \t]+sure)\b/ nocase
        $n4 = /[\[#(<]{1,3}[ \t]*(system|admin|developer|root)[ \t_-]+(override|instructions?|update|notice|command)s?[ \t]*[\]#)>]{1,3}/ nocase
    condition:
        any of them
}

rule cand_ai_vocative {
    strings:
        $voc = /\b(dear|attention|note[ \t]+(to|for)|instructions?[ \t]+(to|for)|message[ \t]+(to|for))[ \t]+(the[ \t]+|any[ \t]+|all[ \t]+)?(ai|llm|llms|language[ \t]+models?|ai[ \t]+assistants?|email[ \t]+assistants?|ai[ \t]+agents?|chatbots?|copilot|chatgpt|claude|gemini)\b/ nocase
        $ifyou = /\bif[ \t]+you[ \t]+are[ \t]+an?[ \t]+(ai|llm|large[ \t]+language[ \t]+model|language[ \t]+model|ai[ \t]+assistant|ai[ \t]+agent|automated[ \t]+(assistant|agent|system))\b/ nocase
        $reading = /\b(ai|llm|ai[ \t]+assistant|ai[ \t]+agent|language[ \t]+model)s?[ \t]+(reading|processing|summari[sz]ing|parsing|reviewing|analy[sz]ing)[ \t]+(this|these)\b/ nocase
    condition:
        any of them
}

rule cand_memory_write {
    strings:
        $m1 = /\b(save|store|add|write|remember|record|keep)[ \t]+(this|that|the[ \t]+following)[ \t]+(to|in|into)[ \t]+(your[ \t]+)?(long[ \t-]?term[ \t]+)?memory\b/ nocase
        $m2 = /\b(in|for|across)[ \t]+(all|every)[ \t]+future[ \t]+(conversations?|sessions?|chats?|interactions?)\b/ nocase
    condition:
        any of them
}

rule cand_policy_puppetry {
    strings:
        $p1 = /<\/?interaction-config>/ nocase
        $p2 = /\bblocked[ \t_-]+(strings|responses|modes)[ \t]*[:=]/ nocase
        $p3 = /\ballowed[ \t_-]+(modes|responses)[ \t]*[:=]/ nocase
    condition:
        any of them
}
