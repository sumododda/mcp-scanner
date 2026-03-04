rule xml_priority_tags {
    meta:
        category = "prompt_injection"
        severity = "CRITICAL"
        description = "XML priority/override tags used to inject hidden instructions"
        cwe = "CWE-1059"
    strings:
        $tag1 = "<IMPORTANT>" nocase
        $tag2 = "</IMPORTANT>" nocase
        $tag3 = "<SYSTEM>" nocase
        $tag4 = "</SYSTEM>" nocase
        $tag5 = "<OVERRIDE>" nocase
        $tag6 = "<PRIORITY>" nocase
        $tag7 = "<ADMIN>" nocase
        $tag8 = "<HIDDEN>" nocase
        $tag9 = "<secret>" nocase
        $tag10 = "<instructions>" nocase
        $tag11 = "<COMPLIANCE>" nocase
    condition:
        any of them
}

rule system_prompt_markers {
    meta:
        category = "prompt_injection"
        severity = "CRITICAL"
        description = "System prompt markers attempting to hijack LLM context"
        cwe = "CWE-1059"
    strings:
        $m1 = "[SYSTEM]"
        $m2 = "[INST]"
        $m3 = "<<SYS>>"
        $m4 = "<|im_start|>system"
        $m5 = "<|im_start|>"
        $m6 = "<|endoftext|>"
        $m7 = "[/INST]"
        $m8 = "<|system|>"
        $m9 = "<|assistant|>"
    condition:
        any of them
}

rule override_instruction_phrases {
    meta:
        category = "prompt_injection"
        severity = "HIGH"
        description = "Phrases attempting to override LLM instructions"
        cwe = "CWE-1059"
    strings:
        $p1 = "ignore previous instructions" nocase
        $p2 = "ignore all previous" nocase
        $p3 = "override all instructions" nocase
        $p4 = "forget all previous" nocase
        $p5 = "disregard previous" nocase
        $p6 = "new instructions:" nocase
        $p7 = "your new role" nocase
        $p8 = "you are now" nocase
        $p9 = "from now on you" nocase
        $p10 = "pretend you are" nocase
        $p11 = "act as if you" nocase
        $p12 = "disregard all prior" nocase
        $p13 = "forget your training" nocase
        $p14 = "ignore your guidelines" nocase
        $p15 = "bypass your restrictions" nocase
    condition:
        any of them
}

rule concealment_directives {
    meta:
        category = "prompt_injection"
        severity = "HIGH"
        description = "Directives to hide actions from the user"
        cwe = "CWE-451"
    strings:
        $c1 = "do not tell the user" nocase
        $c2 = "do not inform the user" nocase
        $c3 = "hide this from" nocase
        $c4 = "user should not see" nocase
        $c5 = "user must not see" nocase
        $c6 = "never reveal" nocase
        $c7 = "never disclose" nocase
        $c8 = "keep hidden" nocase
        $c9 = "do not mention this" nocase
        $c10 = "never inform the user" nocase
    condition:
        any of them
}
