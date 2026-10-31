rule agent_override_imperative {
    meta:
        author = "yara-gate"
        description = "Second-person override, restriction-removal, persona-swap, authority-spoof, or memory-poisoning instruction to an agent"
        intent = "Note on the instruction shapes in the CyClaw injection red-team corpus that agent_prompt_injection_phrases does not cover: override synonyms (guidance, directives), disable or bypass your filters, a persona with no rules, a message from your creators or the IT department that orders compliance, and a request to store a standing instruction in memory. The invoke-tool-to-send and decode-and-execute orders are agent_tool_hijack_directive and stay advisory. Each needs the object it acts on, so a README that says run this command, enable developer mode, or act as a reviewer stays clean"
        severity = "note"
        verdict_on_match = "note"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
        reference_attack = "https://atlas.mitre.org/techniques/AML.T0051"
    strings:
        // "Disregard all prior guidance", "ignore all earlier directives", "forget your original guidelines".
        // "Instructions" is left to agent_prompt_injection_phrases, which keeps its documentary exemption.
        $override = /\b(ignore|disregard|forget)([ \t]+|[ \t]*\r?\n[ \t]*)((all|any)([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?((the|your|my)([ \t]+|[ \t]*\r?\n[ \t]*))?((previous|prior|preceding|earlier|above|initial|original|existing|current|system)([ \t]+|[ \t]*\r?\n[ \t]*))?|(the|your|my)([ \t]+|[ \t]*\r?\n[ \t]*)(previous|prior|preceding|earlier|above|initial|original)([ \t]+|[ \t]*\r?\n[ \t]*)|(previous|prior|preceding|earlier|initial|original)([ \t]+|[ \t]*\r?\n[ \t]*))(directives|guidance|guidelines|safety([ \t]+|[ \t]*\r?\n[ \t]*)(rules|checks|guidelines|filters))\b/ nocase ascii wide
        $override_bare = /\b(override|overwrite)[ \t]+((all|your|the)[ \t]+)?(previous[ \t]+|prior[ \t]+|system[ \t]+)?(instructions|guidelines|safety[ \t]+(rules|filters|settings))[ \t]*[:,]/ nocase ascii wide
        // "Disable your filters", "please bypass restrictions", "remove your guardrails".
        $unrestrict = /\b(disable|bypass|remove|drop|turn[ \t]+off|switch[ \t]+off|ignore)[ \t]+your[ \t]+(safety[ \t]+)?(filters?|restrictions|guardrails|safeguards|safety|content[ \t]+(filters?|policy)|guidelines|rules)\b|\bplease[ \t]+(bypass|disable|ignore|turn[ \t]+off)[ \t]+((the|all|any)[ \t]+)?(safety[ \t]+)?(filters?|restrictions|guardrails|safeguards)\b/ nocase ascii wide
        // A persona with the restrictions stripped off.
        $persona = /\b(pretend[ \t]+(to[ \t]+be|you[ \t]+are)|role-?play[ \t]+as|behave[ \t]+as|(from[ \t]+now[ \t]+on,?[ \t]+)?you[ \t]+(will|must|shall)[ \t]+(now[ \t]+)?(act|behave|respond)[ \t]+as)\b[^\r\n.]{0,64}\b((no|without)[ \t]+(any[ \t]+)?(rules|restrictions|filters|limits|limitations|guardrails|guidelines|ethics|safety|censorship)|unfiltered|unrestricted|uncensored|jailbroken)\b/ nocase ascii wide
        $no_longer = /\byou[ \t]+are[ \t]+no[ \t]+longer[ \t]+(bound|restricted|limited|governed|constrained)[ \t]+by\b/ nocase ascii wide
        $mode = /\b(developer|sudo|god|admin|debug|unrestricted|jailbreak)[ \t]+mode\b[^\r\n.]{0,48}\b((no|without)[ \t]+(any[ \t]+)?(restrictions|filters|limits|rules|guardrails|safety)|grant[ \t]+(me[ \t]+)?root[ \t]+access|(disable|drop|remove)[ \t]+(the[ \t]+|your[ \t]+|all[ \t]+)?(safety|filters?|gate|guardrails))\b/ nocase ascii wide
        $dan = /\bDAN[ \t]+mode\b|\b(?i:do[ \t]+anything[ \t]+now)\b[^\r\n.]{0,24}\b(?i:(no|without)[ \t]+(limits|restrictions|rules|filters))\b/ ascii wide
        // Authority spoof that also gives an order.
        $authority = /\b(critical|urgent|important|mandatory|emergency)[ \t]+update[ \t]+to[ \t]+your[ \t]+(instructions|rules|guidelines|programming|system[ \t]+prompt)\b|\bdeveloper[ \t]+override[ \t]+(engaged|enabled|activated|active|mode)\b/ nocase ascii wide
        $authority_order = /\b(message|update|order|notice|directive)[ \t]+from[ \t]+(your[ \t]+(creators?|developers?|makers?|administrator|admins?)|the[ \t]+(system[ \t]+administrator|IT[ \t]+department|security[ \t]+team)|system[ \t]+administrator|the[ \t]+developers)\b[^\r\n]{0,64}\b(comply|obey|you[ \t]+must|ignore|override|disable|reset[ \t]+your|turn[ \t]+off)\b/ nocase ascii wide
        $it_order = /\bfrom[ \t]+the[ \t]+(IT[ \t]+department|system[ \t]+administrator|security[ \t]+team)[ \t]*:[^\r\n]{0,48}\b(reset|disable|remove|turn[ \t]+off|bypass)[ \t]+your[ \t]+(safety|filters?|guardrails|restrictions|config|configuration|settings)\b/ nocase ascii wide
        // A standing instruction planted in memory. A remembered preference stays clean, and a remembered
        // bypass is agent_persistent_instruction.
        $memory = /\bremember[ \t]+(this[ \t]+)?for[ \t]+(the[ \t]+)?future([ \t]+(sessions|conversations|chats))?[ \t]*:[ \t]*(always|never)[ \t]+(trust|obey|follow|accept|run|execute|share|send)\b|\b(save|store|keep|write)[ \t]+(this|that|the[ \t]+following)[ \t]+(in|to|into)[ \t]+your[ \t]+(long-term[ \t]+)?(memory|knowledge[ \t]+base)\b|\bstore[ \t]+this[ \t]+as[ \t]+(a[ \t]+)?(core[ \t]+instruction|permanent[ \t]+rule|standing[ \t]+order|rule)\b|\badd[ \t]+(this[ \t]+)?to[ \t]+your[ \t]+(knowledge|memory)([ \t]+base)?[ \t]*:|\bupdate[ \t]+your[ \t]+(soul|system[ \t]+prompt|core[ \t]+instructions|memory|persona)[ \t]+to[ \t]+(remove|disable|skip|ignore|bypass|always|never|trust)\b|\bpersist[ \t]+this[^\r\n]{0,24}\bacross[ \t]+sessions[ \t]*:/ nocase ascii wide
        $system_order = /\b(system[ \t]+prompt|new[ \t]+instructions?)[ \t]*:[^\r\n]{0,64}\b(you[ \t]+must[ \t]+comply|comply[ \t]+with[ \t]+all|obey|reveal|disclose|disable|bypass|skip[ \t]+the)\b/ nocase ascii wide
    condition:
        any of them
}
