rule reverse_shell_bash {
    meta:
        category = "shell_injection"
        severity = "CRITICAL"
        description = "Bash reverse shell patterns"
        cwe = "CWE-78"
    strings:
        $rs1 = /bash\s+-i\s+>&\s*\/dev\/tcp\// nocase
        $rs2 = "/dev/tcp/"
        $rs3 = /nc\s+-e\s+\/bin\/(sh|bash)/ nocase
        $rs4 = /ncat\s+.*-e\s+\/bin\/(sh|bash)/ nocase
    condition:
        any of them
}

rule reverse_shell_python {
    meta:
        category = "shell_injection"
        severity = "CRITICAL"
        description = "Python reverse shell patterns"
        cwe = "CWE-78"
    strings:
        $py1 = /python[23]?\s+-c\s+['"]import\s+socket/ nocase
        $py2 = "socket.socket(socket.AF_INET" nocase
        $py3 = "subprocess.call(['/bin/sh'" nocase
        $py4 = "subprocess.call(['/bin/bash'" nocase
    condition:
        any of ($py1, $py3, $py4) or ($py2)
}

rule pipe_execution {
    meta:
        category = "shell_injection"
        severity = "CRITICAL"
        description = "Piped remote code execution patterns"
        cwe = "CWE-78"
    strings:
        $pe1 = /curl\s+[^\|]*\|\s*(sh|bash|python|perl)/ nocase
        $pe2 = /wget\s+[^\|]*\|\s*(sh|bash|python|perl)/ nocase
        $pe3 = /curl\s+[^\|]*\|\s*sudo\s+(sh|bash)/ nocase
    condition:
        any of them
}

rule destructive_commands {
    meta:
        category = "shell_injection"
        severity = "HIGH"
        description = "Destructive shell commands"
        cwe = "CWE-78"
    strings:
        $dc1 = /rm\s+-[rf]{1,2}\s+[\/~]/ nocase
        $dc2 = /mkfs\s+/ nocase
        $dc3 = /dd\s+if=/ nocase
        $dc4 = /chmod\s+777\s+[\/~]/ nocase
        $dc5 = /:\(\)\{.*:\|:.*\}/ nocase
    condition:
        any of them
}

rule eval_exec_patterns {
    meta:
        category = "shell_injection"
        severity = "HIGH"
        description = "Dynamic code execution patterns in descriptions"
        cwe = "CWE-95"
    strings:
        $e1 = /eval\s*\$\(/ nocase
        $e2 = /exec\s*\(/ nocase
        $e3 = /os\.system\s*\(/ nocase
        $e4 = /subprocess\.call\s*\(/ nocase
        $e5 = /child_process\.exec\s*\(/ nocase
    condition:
        any of them
}
