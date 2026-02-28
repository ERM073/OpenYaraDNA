/*
 * YARA Rules - Trojan Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade Trojan detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Trojan_RemoteAccess_Generic
{
    meta:
        author      = "AnonLabs"
        description = "Detects generic Remote Access Trojan (RAT) behavior patterns"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "trojan"

    strings:
        $cmd1  = "cmd.exe /c"        ascii wide nocase
        $rat1  = "RemoteShell"       ascii wide
        $rat2  = "reverse_shell"     ascii wide nocase
        $api1  = "WSAStartup"        ascii wide
        $api2  = "connect"           ascii wide
        $api3  = "recv"              ascii wide
        $api4  = "send"              ascii wide
        $api5  = "CreateProcessA"    ascii wide
        $hide1 = "SW_HIDE"           ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $cmd1 and
        (3 of ($api*)) and
        ($hide1 or 1 of ($rat*))
}


rule Trojan_AgentTesla_Infostealer
{
    meta:
        author      = "AnonLabs"
        description = "Detects Agent Tesla infostealer trojan"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "trojan"

    strings:
        $s1 = "AgentTesla"            ascii wide nocase
        $s2 = "getKeylogger"          ascii wide
        $s3 = "GetPasswordVault"      ascii wide
        $s4 = "smtp.gmail.com"        ascii wide nocase
        $s5 = "GetOutlookPasswords"   ascii wide
        $s6 = "screenshotManager"     ascii wide nocase
        $cfg1 = "SmtpServer"         ascii wide
        $cfg2 = "EmailPassword"      ascii wide
        $obf1 = { 00 54 00 68 00 69 00 73 00 50 00 72 } /* "ThisPr" wide */

    condition:
        uint16(0) == 0x5A4D and
        filesize < 8MB and
        (3 of ($s*) or (1 of ($cfg*) and 2 of ($s*)))
}


rule Trojan_AsyncRAT
{
    meta:
        author      = "AnonLabs"
        description = "Detects AsyncRAT remote access trojan"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "trojan"

    strings:
        $s1 = "AsyncRAT"          ascii wide
        $s2 = "Async-RAT"         ascii wide
        $s3 = "AsyncClient"       ascii wide
        $s4 = "Pastebin"          ascii wide nocase
        $s5 = "GetAntiVirus"      ascii wide
        $s6 = "OfflineKeylogger"  ascii wide
        $pdb = "AsyncRAT\\Client" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($s*) or $pdb)
}


rule Trojan_Loader_Suspicious_Injection
{
    meta:
        author      = "AnonLabs"
        description = "Detects process injection patterns commonly used by trojan loaders"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "trojan"

    strings:
        $api1 = "VirtualAllocEx"    ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "OpenProcess"        ascii wide
        $api5 = "NtUnmapViewOfSection" ascii wide
        $api6 = "ZwUnmapViewOfSection" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (($api1 and $api2 and $api3 and $api4) or
         ($api5 and $api1 and $api2))
}
