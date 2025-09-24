
rule Suspicious_CreateRemoteThread
{
    meta:
        description = "Detects CreateRemoteThread API call"
        family = "injection"
        
    strings:
        $api = "CreateRemoteThread"
        
    condition:
        $api
}

rule Ransomware_Keywords
{
    meta:
        description = "Detects ransomware-related keywords"
        family = "ransomware"
        
    strings:
        $ransom1 = "ransom" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = "payment" nocase
        
    condition:
        any of them
}

rule Trojan_Backdoor
{
    meta:
        description = "Detects backdoor functionality"
        family = "trojan"
        
    strings:
        $backdoor1 = "backdoor" nocase
        $backdoor2 = "remote access" nocase
        $backdoor3 = "shell" nocase
        
    condition:
        any of them
}
