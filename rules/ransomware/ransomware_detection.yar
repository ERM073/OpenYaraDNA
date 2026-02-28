/*
 * YARA Rules - Ransomware Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade ransomware detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Ransomware_Generic_FileEnumeration
{
    meta:
        author      = "AnonLabs"
        description = "Detects ransomware-like file enumeration combined with encryption API usage"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "ransomware"

    strings:
        $api1 = "FindFirstFileW" ascii wide
        $api2 = "FindNextFileW"  ascii wide
        $api3 = "CryptEncrypt"   ascii wide
        $api4 = "CryptGenKey"    ascii wide
        $ext1 = ".locked"        ascii wide nocase
        $ext2 = ".encrypted"     ascii wide nocase
        $ext3 = ".enc"           ascii wide nocase
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "HOW TO RESTORE" ascii wide nocase
        $note3 = "DECRYPT INSTRUCTIONS" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (2 of ($api*)) and
        (1 of ($ext*) or 1 of ($note*))
}


rule Ransomware_WannaCry_Variant
{
    meta:
        author      = "AnonLabs"
        description = "Detects WannaCry and close variants based on unique string artifacts"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "critical"
        category    = "ransomware"

    strings:
        $s1 = "WanaDecryptor"     ascii wide
        $s2 = "WANACRY!"         ascii
        $s3 = "tasksche.exe"     ascii wide
        $s4 = "mssecsvc.exe"     ascii wide
        $s5 = "@WanaDecryptor@"  ascii wide
        $s6 = "lhdfrgui.exe"     ascii wide
        $tor1 = "gx7ekbenv2riucmf.onion" ascii
        $tor2 = "57g7spgrzlojinas.onion" ascii

    condition:
        uint16(0) == 0x5A4D and
        (3 of ($s*) or 1 of ($tor*))
}


rule Ransomware_LockBit_Indicator
{
    meta:
        author      = "AnonLabs"
        description = "Detects LockBit ransomware family indicators"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "critical"
        category    = "ransomware"

    strings:
        $s1 = "LockBit"              ascii wide nocase
        $s2 = "Restore-My-Files.txt" ascii wide
        $s3 = "lockbit"              ascii wide nocase
        $s4 = ".lockbit"             ascii wide
        $ransom1 = "All your files are stolen and encrypted" ascii wide nocase
        $mutex1  = "Global\\{" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (2 of ($s*) or ($ransom1 and $mutex1))
}


rule Ransomware_ShadowCopy_Deletion
{
    meta:
        author      = "AnonLabs"
        description = "Detects ransomware that deletes shadow copies (common pre-encryption step)"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "ransomware"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe Delete Shadows /All" ascii wide nocase
        $vss3 = "Win32_ShadowCopy" ascii wide
        $bcdedit = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase

    condition:
        filesize < 20MB and
        (2 of them)
}
