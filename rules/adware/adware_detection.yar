/*
 * YARA Rules - Adware Detection
 * Author: AnonLabs
 * Reference: https://github.com/ERM073/OpenYaraDNA
 * Description: Production-grade adware detection rules with low false-positive rate.
 * Version: 1.0
 */

rule Adware_Browser_Extension_Injector
{
    meta:
        author      = "AnonLabs"
        description = "Detects adware that installs malicious browser extensions for ad injection"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "medium"
        category    = "adware"

    strings:
        $chrome1 = "\\Google\\Chrome\\User Data\\Default\\Extensions\\" ascii wide nocase
        $ff1     = "\\Mozilla\\Firefox\\Profiles\\" ascii wide nocase
        $ext1    = "manifest.json" ascii wide nocase
        $ext2    = "content_scripts" ascii nocase
        $ext3    = "permissions" ascii nocase
        $reg1    = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Google\\Chrome\\Extensions" ascii wide nocase
        $inj1    = "document.write" ascii nocase
        $inj2    = "insertAdjacentHTML" ascii nocase

    condition:
        filesize < 10MB and
        (1 of ($chrome1,$ff1)) and
        (1 of ($ext*)) and
        (1 of ($reg1,$inj1,$inj2))
}


rule Adware_Search_Hijacker
{
    meta:
        author      = "AnonLabs"
        description = "Detects adware that hijacks browser search settings and homepage"
        reference   = "https://github.com/ERM073/OpenYaraDNA"
        date        = "2024-01-01"
        version     = "1.0"
        severity    = "medium"
        category    = "adware"

    strings:
        $reg1  = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main" ascii wide nocase
        $reg2  = "Start Page"     ascii wide nocase
        $reg3  = "Search Page"    ascii wide nocase
        $pref1 = "user_pref(\"browser.startup.homepage" ascii nocase
        $pref2 = "user_pref(\"keyword.URL" ascii nocase
        $url1  = "search.yahoo.com" ascii wide nocase
        $url2  = "bing.com/search" ascii wide nocase
        $block = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer" ascii wide nocase

    condition:
        filesize < 5MB and
        ($reg1 and 1 of ($reg2,$reg3)) and
        (1 of ($pref*) or 1 of ($url*) or $block)
}
