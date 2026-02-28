/*
 * YARA Rules - Banking Trojan Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade banking trojan detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Banker_WebInject_Patterns
{
    meta:
        author      = "AnonLabs"
        description = "Detects banking trojans using web inject techniques to steal credentials"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "critical"
        category    = "banker"

    strings:
        $inject1 = "set_replace_content" ascii wide nocase
        $inject2 = "data_before"         ascii wide nocase
        $inject3 = "data_inject"         ascii wide nocase
        $inject4 = "data_after"          ascii wide nocase
        $inject5 = "WebFakes"            ascii wide nocase
        $target1 = "bankofamerica"       ascii wide nocase
        $target2 = "paypal.com"          ascii wide nocase
        $target3 = "chase.com"           ascii wide nocase
        $hook1   = "HttpSendRequestA"    ascii wide
        $hook2   = "InternetReadFile"    ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (2 of ($inject*)) and
        (1 of ($target*)) and
        (1 of ($hook*))
}


rule Banker_Zeus_Indicators
{
    meta:
        author      = "AnonLabs"
        description = "Detects Zeus banking trojan and ZeuS-based variants"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "critical"
        category    = "banker"

    strings:
        $s1 = "zbot"            ascii wide nocase
        $s2 = "zeus"            ascii wide nocase
        $s3 = "local.ds"        ascii
        $s4 = "user.ds"         ascii
        $s5 = "nss3.dll"        ascii wide nocase
        $s6 = "PK11_GetInternalKeySlot" ascii wide
        $s7 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Network" ascii wide
        $cfg = { 78 9C }  /* zlib compressed config header */

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (($s3 and $s4) or
         (2 of ($s1,$s2,$s5,$s6)) or
         ($s7 and $cfg))
}


rule Banker_Emotet_Loader
{
    meta:
        author      = "AnonLabs"
        description = "Detects Emotet banking trojan loader characteristics"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "critical"
        category    = "banker"

    strings:
        $s1  = "Emotet"          ascii wide nocase
        $s2  = "geodo"           ascii wide nocase
        $pdb = "emotet"          ascii wide nocase
        /* Emotet uses AES-128 CBC for C2 */
        $enc1 = "CryptDecrypt"   ascii wide
        $enc2 = "CryptImportKey" ascii wide
        /* Named pipe for IPC */
        $pipe = "\\\\.\\pipe\\"  ascii wide
        /* Registry persistence */
        $reg  = "CurrentVersion\\Run" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($s*) or $pdb) and
        ($enc1 and $enc2) and
        ($pipe or $reg)
}


rule Banker_TrickBot_Module
{
    meta:
        author      = "AnonLabs"
        description = "Detects TrickBot banking trojan module artifacts"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "critical"
        category    = "banker"

    strings:
        $s1  = "systeminfo"       ascii wide nocase
        $s2  = "module64.dll"     ascii wide nocase
        $s3  = "module32.dll"     ascii wide nocase
        $s4  = "trickbot"         ascii wide nocase
        $s5  = "TrickLoader"      ascii wide nocase
        $cfg1 = "<mcconf>"        ascii nocase
        $cfg2 = "<server>"        ascii nocase
        $cfg3 = "<autorun>"       ascii nocase
        $cfg4 = "<BOTID>"         ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (2 of ($s*) or 3 of ($cfg*))
}
