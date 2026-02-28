/*
 * YARA Rules - Backdoor Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade backdoor detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Backdoor_WebShell_Generic
{
    meta:
        author      = "AnonLabs"
        description = "Detects generic PHP/ASP/JSP web shell backdoors"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "critical"
        category    = "backdoor"

    strings:
        $php1 = "eval(base64_decode("     ascii nocase
        $php2 = "system($_POST"           ascii nocase
        $php3 = "passthru($_GET"          ascii nocase
        $php4 = "shell_exec($_REQUEST"    ascii nocase
        $php5 = "exec(base64_decode"      ascii nocase
        $asp1 = "eval(Request("           ascii nocase
        $asp2 = "Execute(Request("        ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii nocase

    condition:
        filesize < 1MB and
        (1 of ($php*) or 1 of ($asp*) or $jsp1)
}


rule Backdoor_Cobalt_Strike_Beacon
{
    meta:
        author      = "AnonLabs"
        description = "Detects Cobalt Strike beacon shellcode and stager patterns"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "critical"
        category    = "backdoor"

    strings:
        /* CS default pipe name pattern */
        $pipe1 = "\\\\.\\pipe\\mojo." ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        /* CS beacon config markers */
        $cfg1  = { 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                   00 00 00 00 00 00 00 00 }
        $s1    = "beacon.dll"         ascii nocase
        $s2    = "ReflectiveLoader"   ascii wide
        $s3    = "CobaltStrike"       ascii wide nocase
        $s4    = "cobaltstrike"       ascii wide nocase
        $sleep = "sleep_mask"         ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (1 of ($pipe*) or $cfg1 or 2 of ($s*) or ($s2 and $sleep))  // ← $cfg1を追加
}


rule Backdoor_Reverse_Shell_PowerShell
{
    meta:
        author      = "AnonLabs"
        description = "Detects PowerShell-based reverse shell backdoors"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "backdoor"

    strings:
        $ps1 = "System.Net.Sockets.TCPClient" ascii nocase
        $ps2 = "System.Net.Sockets.NetworkStream" ascii nocase
        $ps3 = "System.IO.StreamReader" ascii nocase
        $ps4 = "System.IO.StreamWriter" ascii nocase
        $ps5 = "powershell -nop -w hidden" ascii nocase
        $ps6 = "IEX (New-Object Net.WebClient)" ascii nocase
        $enc = "FromBase64String" ascii nocase

    condition:
        filesize < 2MB and
        (($ps1 and $ps2 and ($ps3 or $ps4)) or
         ($ps5 and $enc) or
         ($ps6 and $enc))
}


rule Backdoor_SSH_Authorized_Keys_Abuse
{
    meta:
        author      = "AnonLabs"
        description = "Detects malware that writes unauthorized SSH keys for persistent access"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "backdoor"

    strings:
        $s1 = "authorized_keys"  ascii wide
        $s2 = "ssh-rsa AAAA"     ascii
        $s3 = "ssh-ed25519 AAAA" ascii
        $s4 = ".ssh/"            ascii wide
        $api1 = "fopen"          ascii wide
        $api2 = "fputs"          ascii wide
        $api3 = "chmod"          ascii wide

    condition:
        filesize < 5MB and
        ($s1 and ($s2 or $s3) and $s4) and
        (1 of ($api*))
}
