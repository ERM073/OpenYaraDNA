/*
 * YARA Rules - Dropper / Loader Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade dropper/loader detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Dropper_Generic_Temp_Write_Execute
{
    meta:
        author      = "AnonLabs"
        description = "Detects droppers that write payloads to temp directories and execute them"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "dropper"

    strings:
        $tmp1 = "%TEMP%\\"         ascii wide nocase
        $tmp2 = "%TMP%\\"          ascii wide nocase
        $tmp3 = "\\Temp\\"         ascii wide nocase
        $api1 = "WriteFile"        ascii wide
        $api2 = "CreateFileA"      ascii wide
        $api3 = "WinExec"          ascii wide
        $api4 = "ShellExecuteA"    ascii wide
        $api5 = "CreateProcessA"   ascii wide
        $api6 = "ExpandEnvironmentStringsA" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (1 of ($tmp*)) and
        ($api1 or $api2) and
        (1 of ($api3,$api4,$api5))
}


rule Dropper_SFX_Embedded_Payload
{
    meta:
        author      = "AnonLabs"
        description = "Detects self-extracting archive droppers with embedded executable payloads"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "dropper"

    strings:
        /* MZ header of embedded PE */
        $pe_embedded = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
        $sfx1 = "SFX"             ascii wide nocase
        $sfx2 = "self-extract"    ascii wide nocase
        $sfx3 = "WinZip Self-Extractor" ascii wide nocase
        $sfx4 = "7-Zip SFX"      ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        /* Second PE header found inside file (offset > 0x100) */
        for any i in (0x100..filesize - 14) : ( @pe_embedded[1] > 0x100 ) and
        (1 of ($sfx*))
}


rule Dropper_Powershell_Download_Execute
{
    meta:
        author      = "AnonLabs"
        description = "Detects dropper scripts that download and execute secondary payloads via PowerShell"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "dropper"

    strings:
        $dl1 = "DownloadFile("        ascii nocase
        $dl2 = "DownloadString("      ascii nocase
        $dl3 = "WebClient"            ascii nocase
        $dl4 = "BitsTransfer"         ascii nocase
        $ex1 = "Invoke-Expression"    ascii nocase
        $ex2 = "IEX"                  ascii nocase
        $ex3 = "Start-Process"        ascii nocase
        $ex4 = "Invoke-Item"          ascii nocase
        $enc1 = "-EncodedCommand"     ascii nocase
        $enc2 = "FromBase64String"    ascii nocase

    condition:
        filesize < 2MB and
        (1 of ($dl*)) and
        (1 of ($ex*)) and
        (1 of ($enc*))
}
