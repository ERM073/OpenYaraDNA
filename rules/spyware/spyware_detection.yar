/*
 * YARA Rules - Spyware Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade spyware detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Spyware_Generic_Screenshot_Exfil
{
    meta:
        author      = "AnonLabs"
        description = "Detects spyware that captures screenshots and exfiltrates data"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "spyware"

    strings:
        $ss1  = "BitBlt"             ascii wide
        $ss2  = "GetDC"              ascii wide
        $ss3  = "CreateCompatibleDC" ascii wide
        $net1 = "HttpSendRequestA"   ascii wide
        $net2 = "InternetOpenA"      ascii wide
        $net3 = "URLDownloadToFileA" ascii wide
        $path1 = "\\AppData\\Roaming\\" ascii wide nocase
        $path2 = "%TEMP%\\"         ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (2 of ($ss*)) and
        (1 of ($net*)) and
        (1 of ($path*))
}


rule Spyware_Pegasus_Indicators
{
    meta:
        author      = "AnonLabs"
        description = "Detects indicators associated with Pegasus spyware artifacts on endpoints"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "critical"
        category    = "spyware"

    strings:
        $s1 = "bh_1.dat"      ascii
        $s2 = "mds.db"        ascii
        $s3 = "AMPAgent"      ascii
        $s4 = "Pegasus"       ascii wide nocase
        $s5 = "NSO Group"     ascii wide nocase
        $proc1 = "msgaccount" ascii
        $proc2 = "roleaboutd"  ascii
        $proc3 = "roleaccountd" ascii

    condition:
        2 of ($s*) or 2 of ($proc*)
}


rule Spyware_Clipboard_Monitor
{
    meta:
        author      = "AnonLabs"
        description = "Detects spyware that monitors clipboard content (often for crypto wallet theft)"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "medium"
        category    = "spyware"

    strings:
        $api1  = "OpenClipboard"     ascii wide
        $api2  = "GetClipboardData"  ascii wide
        $api3  = "SetClipboardData"  ascii wide
        $api4  = "CloseClipboard"    ascii wide
        $timer = "SetTimer"          ascii wide
        $net1  = "HttpOpenRequestA"  ascii wide
        $btc   = "1[13456789A-HJ-NP-Za-km-z]{25,34}" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($api1 and $api2 and $api4) and
        ($api3 or $timer) and
        $net1
}
