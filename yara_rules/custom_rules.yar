/*
  FileScanner Custom YARA Rules
  Meaningful detection rules separating confirmed malware from heuristic warnings.
*/

rule EICAR_Antivirus_Test
{
    meta:
        description = "Standard EICAR Antivirus Test File"
        threat_category = "malware"
        severity = "CRITICAL"
        threat_type = "test_signature"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Obfuscated_Powershell
{
    meta:
        description = "Suspicious obfuscated PowerShell download cradle or hidden execution"
        threat_category = "suspicious_script"
        severity = "HIGH"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $iex = "IEX" nocase
        $b64 = "FromBase64String" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        ($ps1 or $ps2) and (($enc1 or $enc2) or ($hidden and $bypass) or ($iex and ($dl1 or $dl2 or $b64)))
}

rule Suspicious_JavaScript_Eval_Unescape
{
    meta:
        description = "Obfuscated JavaScript payload using eval and unescape/fromCharCode"
        threat_category = "suspicious_script"
        severity = "HIGH"
    strings:
        $s1 = /eval\s*\(\s*unescape\s*\(/ nocase
        $s2 = /eval\s*\(\s*atob\s*\(/ nocase
        $s3 = /document\.write\s*\(\s*unescape\s*\(/ nocase
        $s4 = /String\.fromCharCode\s*\(\s*([0-9]{1,3}\s*,\s*){8,}/ nocase
    condition:
        any of ($s*)
}

rule PHP_Webshell_Backdoor
{
    meta:
        description = "PHP Webshell backdoor dynamic code execution"
        threat_category = "malware"
        severity = "CRITICAL"
    strings:
        $php = "<?php" nocase
        $e1 = /eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $e2 = /(system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $e3 = /assert\s*\(\s*base64_decode\s*\(/ nocase
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
    condition:
        $php and (any of ($e*) or $c99 or $r57)
}

rule Suspicious_Ransomware_Shadow_Deletion
{
    meta:
        description = "Shadow copy deletion and recovery tampering commands"
        threat_category = "malware"
        severity = "CRITICAL"
    strings:
        $vss = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $bcd = /bcdedit(\.exe)?\s+\/set\s+\{[a-zA-Z0-9_\-]+\}\s+bootstatuspolicy\s+ignoreallfailures/ nocase
        $wbadm = /wbadmin(\.exe)?\s+delete\s+catalog\s+-quiet/ nocase
        $wmic = /wmic(\.exe)?\s+shadowcopy\s+delete/ nocase
    condition:
        any of them
}

rule Suspicious_VBA_Macro_Execution
{
    meta:
        description = "Suspicious Microsoft Office VBA Macro with auto-execution and shell/download"
        threat_category = "suspicious_script"
        severity = "HIGH"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Workbook_Open" nocase
        $auto3 = "Document_Open" nocase
        $exec1 = "ShellExecute" nocase
        $exec2 = "WScript.Shell" nocase
        $exec3 = "URLDownloadToFile" nocase
        $exec4 = "CreateObject(\"WScript.Shell\")" nocase
    condition:
        any of ($auto*) and any of ($exec*)
}

rule Phishing_Credential_Harvesting_Pattern
{
    meta:
        description = "Suspicious HTML phishing form soliciting credentials to external destinations"
        threat_category = "phishing"
        severity = "MEDIUM"
    strings:
        $input_pwd = /<input[^>]+type=["']password["']/ nocase
        $form_post = /<form[^>]+method=["']post["'][^>]+action=["'](https?:\/\/[^"'>]+)["']/ nocase
        $keyw1 = "verify your account" nocase
        $keyw2 = "confirm your password" nocase
        $keyw3 = "session expired" nocase
        $keyw4 = "sign in to continue" nocase
    condition:
        $input_pwd and $form_post and (1 of ($keyw*))
}

