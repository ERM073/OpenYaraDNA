/*
 * YARA Rules - Backdoor Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade backdoor detection rules with low false-positive rate.
 * Version: 1.0
 */

import "pe"

rule Backdoor_WebShell_Generic
{
    meta:
        author      = "AnonLabs"
        description = "Detects generic PHP/ASP/JSP web shell backdoors"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-03"
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
        $php6 = "assert(base64_decode"    ascii nocase
        $php7 = "preg_replace(/./e"       ascii nocase
        $php8 = "create_function("        ascii nocase
        $generic1 = "<?php"               ascii
        $generic2 = "<%@ Page"            ascii
        $generic3 = "<%@page"             ascii

    condition:
        filesize < 1MB and
        (
            ($generic1 and 1 of ($php*)) or
            (($generic2 or $generic3) and 1 of ($asp*)) or
            ($jsp1)
        )
}


rule Backdoor_Cobalt_Strike_Beacon
{
    meta:
        author      = "AnonLabs"
        description = "Detects Cobalt Strike beacon shellcode and stager patterns"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-03"
        version     = "1.0"
        severity    = "critical"
        category    = "backdoor"

    strings:
        $pipe1 = "\\\\.\\pipe\\mojo." ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $cfg1  = { 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                   00 00 00 00 00 00 00 00 }
        $s1    = "beacon.dll"         ascii nocase
        $s2    = "ReflectiveLoader"   ascii wide
        $s3    = "CobaltStrike"       ascii wide nocase
        $s4    = "cobaltstrike"       ascii wide nocase
        $sleep = "sleep_mask"         ascii wide nocase
        $s5    = "beacon.x64.dll"     ascii nocase
        $s6    = "beacon.x86.dll"     ascii nocase
        $s7    = "rdll_setup"         ascii wide

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x4D5A) and
        (
            1 of ($pipe*) or
            2 of ($s*) or
            ($s2 and $sleep) or
            ($s7 and 1 of ($s1, $s5, $s6))
        )
}


rule Backdoor_Reverse_Shell_PowerShell
{
    meta:
        author      = "AnonLabs"
        description = "Detects PowerShell-based reverse shell backdoors"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-03"
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
        $ps7 = "$stream.Write" ascii nocase
        $enc = "FromBase64String" ascii nocase
        $obf1 = "powershell -e "          ascii nocase
        $obf2 = "powershell -enc "        ascii nocase
        $obf3 = "powershell -EncodedCommand" ascii nocase
        $obf4 = "Invoke-Expression"       ascii nocase
        $obf5 = "IEX("                    ascii nocase
        $rev1 = "while($true)"            ascii nocase
        $rev2 = "Start-Sleep -m"          ascii nocase

    condition:
        filesize < 2MB and
        (
            ($ps1 and $ps2 and ($ps3 or $ps4)) or
            ($ps5 and $enc) or
            ($ps6 and $enc) or
            ($ps7 and $enc) or  // ← $ps7を追加
            (1 of ($obf*) and $enc and ($rev1 or $rev2))
        )
}


rule Backdoor_SSH_Authorized_Keys_Abuse
{
    meta:
        author      = "AnonLabs"
        description = "Detects malware that writes unauthorized SSH keys for persistent access"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-03"
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
        $s5 = "ssh-dss AAAA"     ascii
        $s6 = "ecdsa-sha2-nistp256 AAAA" ascii
        $s7 = "ssh-ed25519 "     ascii wide
        $api4 = "open("          ascii wide
        $api5 = "write("         ascii wide
        $api6 = "fprintf"        ascii wide
        $path1 = "/root/.ssh/"   ascii wide
        $path2 = "/home/"        ascii wide fullword
        $path3 = "~/.ssh/"       ascii wide

    condition:
        filesize < 5MB and
        (
            ($s1 and ($s2 or $s3 or $s5 or $s6 or $s7)) and
            ($s4 or $path1 or $path2 or $path3) and
            (1 of ($api*))  // ← $api6を含むすべての$api*を参照
        )
}
