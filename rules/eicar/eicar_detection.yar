rule Detect_EICAR_Test_Malware
{
    meta:
        author = "AnonLabs"
        description = "Detects the EICAR standard antivirus test file for educational purposes"
        reference = "https://github.com/ERM073/OpenYaraDNA"
        date = "2026-03-01"

    strings:

        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
