rule hex_escape_sequences {
    meta:
        category = "encoding_evasion"
        severity = "HIGH"
        description = "Hex escape sequences that may encode hidden instructions"
        cwe = "CWE-506"
    strings:
        $hex = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/
    condition:
        $hex
}

rule long_base64_blob {
    meta:
        category = "encoding_evasion"
        severity = "HIGH"
        description = "Long base64-encoded blob that may hide payloads"
        cwe = "CWE-506"
    strings:
        $b64 = /[A-Za-z0-9+\/]{60,}={0,3}/
    condition:
        $b64
}

rule unicode_escape_sequences {
    meta:
        category = "encoding_evasion"
        severity = "HIGH"
        description = "Unicode escape sequences that may encode hidden instructions"
        cwe = "CWE-506"
    strings:
        $uni = /\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}/
    condition:
        $uni
}

rule percent_encoded_payload {
    meta:
        category = "encoding_evasion"
        severity = "MEDIUM"
        description = "Excessive percent-encoding that may hide payloads"
        cwe = "CWE-506"
    strings:
        $pct = /%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}/
    condition:
        $pct
}
