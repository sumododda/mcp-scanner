rule known_exfil_services {
    meta:
        category = "exfiltration"
        severity = "CRITICAL"
        description = "Known data exfiltration service domains"
        cwe = "CWE-200"
    strings:
        $d1 = "webhook.site" nocase
        $d2 = "requestbin.com" nocase
        $d3 = "pipedream.net" nocase
        $d4 = "hookbin.com" nocase
        $d5 = "requestcatcher.com" nocase
        $d6 = "canarytokens.com" nocase
        $d7 = "interact.sh" nocase
        $d8 = "oastify.com" nocase
        $d9 = "requestrepo.com" nocase
    condition:
        any of them
}

rule ngrok_tunnels {
    meta:
        category = "exfiltration"
        severity = "HIGH"
        description = "ngrok tunnel URLs used for data exfiltration"
        cwe = "CWE-200"
    strings:
        $ngrok = /[a-z0-9]+\.ngrok\.io/ nocase
        $ngrok2 = /[a-z0-9]+\.ngrok-free\.app/ nocase
    condition:
        any of them
}

rule burp_collaborator {
    meta:
        category = "exfiltration"
        severity = "HIGH"
        description = "Burp Collaborator URLs used for out-of-band data exfiltration"
        cwe = "CWE-200"
    strings:
        $burp = /[a-z0-9]+\.burpcollaborator\.net/ nocase
        $oast = /[a-z0-9]+\.oast\.fun/ nocase
        $oast2 = /[a-z0-9]+\.oast\.live/ nocase
        $oast3 = /[a-z0-9]+\.oast\.site/ nocase
    condition:
        any of them
}

rule dynamic_dns_exfil {
    meta:
        category = "exfiltration"
        severity = "MEDIUM"
        description = "Dynamic DNS services commonly used for exfiltration"
        cwe = "CWE-200"
    strings:
        $d1 = ".duckdns.org" nocase
        $d2 = ".no-ip.com" nocase
        $d3 = ".serveo.net" nocase
    condition:
        any of them
}

rule data_encoding_exfil {
    meta:
        category = "exfiltration"
        severity = "HIGH"
        description = "Data encoding patterns used for exfiltration via URL parameters"
        cwe = "CWE-200"
    strings:
        $dns_exfil = /[a-z0-9]+\.\$\{/ nocase
        $param_exfil = /\?data=[A-Za-z0-9+\/=]{20,}/
        $param_exfil2 = /\?token=[A-Za-z0-9+\/=]{20,}/
        $param_exfil3 = /\?payload=[A-Za-z0-9+\/=]{20,}/
    condition:
        any of them
}
