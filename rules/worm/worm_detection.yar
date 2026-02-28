/*
 * YARA Rules - Worm Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade worm detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Worm_Network_Self_Propagation
{
    meta:
        author      = "AnonLabs"
        description = "Detects network worms that scan and propagate across hosts"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "worm"

    strings:
        $net1  = "WSAStartup"        ascii wide
        $net2  = "connect"           ascii wide
        $net3  = "send"              ascii wide
        $net4  = "recv"              ascii wide
        $scan1 = "inet_addr"         ascii wide
        $scan2 = "gethostbyname"     ascii wide
        $copy1 = "CopyFileA"         ascii wide
        $copy2 = "CopyFileW"         ascii wide
        $smb1  = "\\IPC$"            ascii wide
        $smb2  = "\\ADMIN$"          ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (3 of ($net*)) and
        (1 of ($scan*)) and
        (1 of ($copy*) or 1 of ($smb*))
}


rule Worm_USB_Removable_Propagation
{
    meta:
        author      = "AnonLabs"
        description = "Detects worms that spread via USB/removable media using autorun tricks"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "worm"

    strings:
        $usb1  = "GetDriveTypeA"     ascii wide
        $usb2  = "GetDriveTypeW"     ascii wide
        $usb3  = "DRIVE_REMOVABLE"   ascii wide
        $auto1 = "autorun.inf"       ascii wide nocase
        $auto2 = "[AutoRun]"         ascii nocase
        $auto3 = "open="             ascii nocase
        $copy1 = "CopyFileA"         ascii wide
        $copy2 = "CopyFileW"         ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (1 of ($usb*)) and
        (1 of ($auto*)) and
        (1 of ($copy*))
}


rule Worm_Email_Mass_Mailer
{
    meta:
        author      = "AnonLabs"
        description = "Detects email worms that use SMTP to spread via address books"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "worm"

    strings:
        $smtp1 = "SMTP"              ascii wide nocase
        $smtp2 = "MAIL FROM:"        ascii nocase
        $smtp3 = "RCPT TO:"          ascii nocase
        $smtp4 = "DATA\r\n"          ascii nocase
        $book1 = "Outlook.Application" ascii wide
        $book2 = "MAPI32.dll"        ascii wide
        $attach = "Content-Disposition: attachment" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (2 of ($smtp*)) and
        (1 of ($book*)) and
        $attach
}
