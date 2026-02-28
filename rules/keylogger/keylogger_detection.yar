/*
 * YARA Rules - Keylogger Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade keylogger detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Keylogger_SetWindowsHookEx
{
    meta:
        author      = "AnonLabs"
        description = "Detects keyloggers using SetWindowsHookEx WH_KEYBOARD hook"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "keylogger"

    strings:
        $api1  = "SetWindowsHookExA"  ascii wide
        $api2  = "SetWindowsHookExW"  ascii wide
        $api3  = "GetAsyncKeyState"   ascii wide
        $api4  = "GetForegroundWindow" ascii wide
        $api5  = "GetWindowTextA"     ascii wide
        $log1  = "keylog"             ascii wide nocase
        $log2  = "keystroke"          ascii wide nocase
        $log3  = "keyboard.log"       ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (1 of ($api1,$api2) or $api3) and
        ($api4 or $api5) and
        (1 of ($log*))
}


rule Keylogger_Raw_Input_Hook
{
    meta:
        author      = "AnonLabs"
        description = "Detects keyloggers using Raw Input API for stealthy key capture"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "keylogger"

    strings:
        $api1 = "RegisterRawInputDevices" ascii wide
        $api2 = "GetRawInputData"        ascii wide
        $api3 = "WM_INPUT"               ascii wide
        $api4 = "RIDEV_INPUTSINK"        ascii wide
        $net1 = "send"                   ascii wide
        $net2 = "InternetOpenA"          ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($api1 and $api2) and
        ($api3 or $api4) and
        (1 of ($net*))
}


rule Keylogger_DirectX_Input
{
    meta:
        author      = "AnonLabs"
        description = "Detects keyloggers leveraging DirectInput to bypass standard hooks"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "medium"
        category    = "keylogger"

    strings:
        $di1  = "DirectInput8Create"   ascii wide
        $di2  = "IDirectInput8"        ascii wide
        $di3  = "GUID_SysKeyboard"     ascii wide
        $log1 = "WriteFile"            ascii wide
        $log2 = "fwrite"               ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($di1 and $di2 and $di3) and
        (1 of ($log*))
}
