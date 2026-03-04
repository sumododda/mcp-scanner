rule aws_access_key {
    meta:
        category = "credential_exposure"
        severity = "CRITICAL"
        description = "AWS access key ID pattern"
        cwe = "CWE-798"
    strings:
        $key = /AKIA[0-9A-Z]{16}/
    condition:
        $key
}

rule aws_secret_key {
    meta:
        category = "credential_exposure"
        severity = "CRITICAL"
        description = "AWS secret access key pattern"
        cwe = "CWE-798"
    strings:
        $secret = /aws_secret_access_key[\s]*[=:][\s]*[A-Za-z0-9\/+=]{40}/
    condition:
        $secret
}

rule private_key_header {
    meta:
        category = "credential_exposure"
        severity = "CRITICAL"
        description = "Private key header in content"
        cwe = "CWE-321"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $generic = "-----BEGIN PRIVATE KEY-----"
    condition:
        any of them
}

rule openai_api_key {
    meta:
        category = "credential_exposure"
        severity = "HIGH"
        description = "OpenAI API key pattern"
        cwe = "CWE-798"
    strings:
        $key = /sk-[A-Za-z0-9]{20,}/
    condition:
        $key
}

rule github_token {
    meta:
        category = "credential_exposure"
        severity = "HIGH"
        description = "GitHub personal access token or fine-grained token"
        cwe = "CWE-798"
    strings:
        $classic = /ghp_[A-Za-z0-9]{36}/
        $fine = /github_pat_[A-Za-z0-9_]{22,}/
        $oauth = /gho_[A-Za-z0-9]{36}/
        $app = /ghs_[A-Za-z0-9]{36}/
    condition:
        any of them
}

rule slack_token {
    meta:
        category = "credential_exposure"
        severity = "HIGH"
        description = "Slack bot or user token"
        cwe = "CWE-798"
    strings:
        $bot = /xoxb-[0-9]{10,}-[0-9a-zA-Z]{20,}/
        $user = /xoxp-[0-9]{10,}-[0-9a-zA-Z]{20,}/
        $app = /xapp-[0-9]{1,}-[A-Za-z0-9]{10,}-[0-9a-zA-Z]{20,}/
    condition:
        any of them
}

rule generic_api_key_assignment {
    meta:
        category = "credential_exposure"
        severity = "MEDIUM"
        description = "Hardcoded API key or secret assignment"
        cwe = "CWE-798"
    strings:
        $a1 = /api_key[\s]*[=:][\s]*["'][A-Za-z0-9]{20,}["']/ nocase
        $a2 = /api_secret[\s]*[=:][\s]*["'][A-Za-z0-9]{20,}["']/ nocase
        $a3 = /password[\s]*[=:][\s]*["'][^"']{8,}["']/ nocase
    condition:
        any of them
}
