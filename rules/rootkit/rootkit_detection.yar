/*
 * YARA Rules - Rootkit Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade rootkit detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Rootkit_DKOM_Techniques
{
    meta:
        author      = "AnonLabs"
        description = "Detects Direct Kernel Object Manipulation (DKOM) techniques used by rootkits"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "critical"
        category    = "rootkit"

    strings:
        $api1 = "PsGetNextProcess"       ascii wide
        $api2 = "PsLookupProcessByProcessId" ascii wide
        $api3 = "ObDereferenceObject"    ascii wide
        $api4 = "MmGetSystemRoutineAddress" ascii wide
        $str1 = "ActiveProcessLinks"     ascii wide
        $str2 = "EPROCESS"              ascii wide
        $str3 = "PspCidTable"           ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (2 of ($api*)) and
        (1 of ($str*))
}


rule Rootkit_MBR_Infection
{
    meta:
        author      = "AnonLabs"
        description = "Detects MBR (Master Boot Record) rootkit infection markers"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "critical"
        category    = "rootkit"

    strings:
        $mbr_sig  = { 55 AA }
        $api1 = "\\\\.\\\\.PhysicalDrive0" ascii wide nocase
        $api2 = "DeviceIoControl"          ascii wide
        $api3 = "CreateFileW"              ascii wide
        $hook1 = "Int13h"                  ascii wide nocase
        $hook2 = "int 0x13"                ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $mbr_sig and
        (2 of ($api*)) and
        (1 of ($hook*))
}


rule Rootkit_Kernel_Driver_Suspicious
{
    meta:
        author      = "AnonLabs"
        description = "Detects suspicious kernel driver characteristics associated with rootkits"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "high"
        category    = "rootkit"

    strings:
        $drv1 = "DriverEntry"         ascii wide
        $drv2 = "IoCreateDevice"      ascii wide
        $drv3 = "IoCreateSymbolicLink" ascii wide
        $hide1 = "ZwQuerySystemInformation" ascii wide
        $hide2 = "NtQueryDirectoryFile"     ascii wide
        $hide3 = "PsSetCreateProcessNotifyRoutine" ascii wide
        $ssdt1 = "KeServiceDescriptorTable" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        ($drv1 and $drv2) and
        (2 of ($hide*) or $ssdt1)
}
