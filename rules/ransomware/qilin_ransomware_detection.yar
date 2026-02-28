/*
 * YARA Rules - Qilin Ransomware Detection
 * Author: AnonLabs
 * Reference: https://theravenfile.com/2025/08/01/inside-qilin-ransomware-affiliates-panel/
 * Description: Detects Qilin ransomware infrastructure, payloads, and artifacts
 * Version: 1.0
 * Date: 2026-03-01
 */

import "hash"

rule Qilin_Ransomware_MD5_Hash
{
    meta:
        author      = "AnonLabs"
        description = "Detects Qilin ransomware samples by MD5 hash"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "critical"
        category    = "ransomware"

    condition:
        hash.md5(0, filesize) == "2bb209ccfc5103eccab523c875050cfa" or
        hash.md5(0, filesize) == "a7e7d00d531cb7ca27d0f3bee448573f" or
        hash.md5(0, filesize) == "964c13b68dc6b6b918b66a9a10469d2a" or
        hash.md5(0, filesize) == "3b10127e65fa3e215d21e0a2e7fd32be" or
        hash.md5(0, filesize) == "d1c331c17ddd4abe0d53755461c1ec9a" or
        hash.md5(0, filesize) == "417ad60624345ef85e648038e18902ab" or
        hash.md5(0, filesize) == "b04e8ee43aba85fa5c585b9335c953c2" or
        hash.md5(0, filesize) == "59d756280b06cf113ca43abc0050edd5" or
        hash.md5(0, filesize) == "88bb86494cb9411a9692f9c8e67ed32c" or
        hash.md5(0, filesize) == "37155f0bca29ccd6b6d4f5b2bc42eb4d" or
        hash.md5(0, filesize) == "e01776ec67b9f1ae780c3e24ecc4bf06" or
        hash.md5(0, filesize) == "11d795baafa44b73766e850d13b8e254" or
        hash.md5(0, filesize) == "88630916b0c6633ca28c8896416a93ee" or
        hash.md5(0, filesize) == "dd42c3e017889c107a81da78d87dc8af" or
        hash.md5(0, filesize) == "1c4bea81c0da22badd9b7eab574c51cd" or
        hash.md5(0, filesize) == "ab05a1925fee8334a2114811d5283364" or
        hash.md5(0, filesize) == "64a590760fdbb84356544cc90ac3d50f" or
        hash.md5(0, filesize) == "2020979e080d7ac9c0403172573c7de8" or
        hash.md5(0, filesize) == "bed0f34673cc93560c17e3ab04ea5d19" or
        hash.md5(0, filesize) == "4a3f22021e4415e8211633fb3735a046" or
        hash.md5(0, filesize) == "6fc6164b3a08669992acad3764fb1922" or
        hash.md5(0, filesize) == "d309e3d77ed6a336eb3ad263ddf9db90" or
        hash.md5(0, filesize) == "575b26c1cc06609722f98e2beaed6a8a" or
        hash.md5(0, filesize) == "a6302fdb63e2244c1246a73a7d65d09e" or
        hash.md5(0, filesize) == "1bde76f3197123dcc2ecd0bfef567484" or
        hash.md5(0, filesize) == "ea1f8794c73b26724314e5356f1f4128" or
        hash.md5(0, filesize) == "9befad1d56d2bd8195813aea1f37f921" or
        hash.md5(0, filesize) == "9f510626c7327a7c2328bc5131726638" or
        hash.md5(0, filesize) == "08a2405cd32f044a69737e77454ee2da" or
        hash.md5(0, filesize) == "fdc6848dad660414bed9ad1b381cf6e3" or
        hash.md5(0, filesize) == "19ff6488a259d750ec18902fe75a713b" or
        hash.md5(0, filesize) == "4ea8adecc5bd45a76cc61430c560924f" or
        hash.md5(0, filesize) == "d6e7547ad7dfd1fbc62e8282aebcc391" or
        hash.md5(0, filesize) == "f588802958c35fe18eb87bc36651a3d1" or
        hash.md5(0, filesize) == "0d68a310f4265821900249bec89364c2" or
        hash.md5(0, filesize) == "53c8a4f0497929de4a5039b2c14bf426" or
        hash.md5(0, filesize) == "670fe8faaede4e2e033311fb662d2a4a" or
        hash.md5(0, filesize) == "f982da00c547913fd0ae7d0da0fc77e7" or
        hash.md5(0, filesize) == "9ea321b6a0f069caab7092cfe1cbbde0" or
        hash.md5(0, filesize) == "2f76a29d4e4292d7f29a29345717812c" or
        hash.md5(0, filesize) == "826a8e8c05983aa3a884d7abcfa473ac" or
        hash.md5(0, filesize) == "8ca5c9745e8a0e18167a9b932821645a" or
        hash.md5(0, filesize) == "5862f9fc9c9a0d766eba29eb4945f619" or
        hash.md5(0, filesize) == "3158a3849ea2695d6ec5aea6512fd030" or
        hash.md5(0, filesize) == "24a8fcd08d9e40d32929b57de9b15385" or
        hash.md5(0, filesize) == "996c394d0f6d6967df9542c52f6f4661" or
        hash.md5(0, filesize) == "420a2c53386678396f972f09cc7f3a5c" or
        hash.md5(0, filesize) == "5cffa3126b9effc279d32b2cf4ef2278" or
        hash.md5(0, filesize) == "348b0ce6af4698061678c8e92b4b2675" or
        hash.md5(0, filesize) == "144183a4217ae0914ba0c865858d07cd" or
        hash.md5(0, filesize) == "6f893b1cc5cf534c59eabe932c1bf21e" or
        hash.md5(0, filesize) == "b4a6152514919a637c22a58bea316fc7" or
        hash.md5(0, filesize) == "a7ab0969bf6641cd0c7228ae95f6d217" or
        hash.md5(0, filesize) == "e4c1add9f7606e3fa57976b908b4b375" or
        hash.md5(0, filesize) == "e7adc46e79fc8a44b986ef77dfb1f4c5" or
        hash.md5(0, filesize) == "2674ad25fabe97a9eb10dcdbd32e4c9d" or
        hash.md5(0, filesize) == "4171f567e0b1f60ab6bb82c85c391fc4" or
        hash.md5(0, filesize) == "eb8cbf0dfc4d5c9f6a9a92e3f9f64327" or
        hash.md5(0, filesize) == "6bef16999793f151cfb6012c34ca951c" or
        hash.md5(0, filesize) == "c716ff8dbcaf477aa386e4843fd79635" or
        hash.md5(0, filesize) == "5d9b5e2e48c3d32993a28526d99daa0e" or
        hash.md5(0, filesize) == "44b610e323a470613649bb183e7a4250" or
        hash.md5(0, filesize) == "a4247610f7194abfe4639868a2f7a446" or
        hash.md5(0, filesize) == "37aeb403ec4979626e2ec85380296439" or
        hash.md5(0, filesize) == "457b4eeb5b9090476ea52ceccdf63c0b" or
        hash.md5(0, filesize) == "aeace70c1d26d699c0221e9acd0a43b2" or
        hash.md5(0, filesize) == "8f946e4b90e434e2865449c212fe70c6" or
        hash.md5(0, filesize) == "dd475afd948cc22caa2a0f934d0aec52" or
        hash.md5(0, filesize) == "a9eaddd0ca6b06ff6c44b02ca9be1936" or
        hash.md5(0, filesize) == "f1dbe4e70de07fd3368915a29b376d1d" or
        hash.md5(0, filesize) == "1c0cb55d3a8d544ab0bd7d81d2985089" or
        hash.md5(0, filesize) == "deba77ce237a412331cda6c87cf62cdc" or
        hash.md5(0, filesize) == "9e4bb27199b9f8ef1c9efebe78703e06" or
        hash.md5(0, filesize) == "b9cb30b2bfc0618c676e998ea9430102" or
        hash.md5(0, filesize) == "227f14f4c3aa35b9fb279f52c73b2e1e" or
        hash.md5(0, filesize) == "22f86cec9a2f32d43673ffb8156eee4f" or
        hash.md5(0, filesize) == "c1b97db9b6cced29fcc4d75f342e9be4" or
        hash.md5(0, filesize) == "80dabe87dee2818816c1b8f79ddac79c" or
        hash.md5(0, filesize) == "586cea3284fe4763fa80fdf66a0ebfd6" or
        hash.md5(0, filesize) == "a5d8608c6bb4874880db60edcd90bbc6" or
        hash.md5(0, filesize) == "f3b531e3c02bf043db87ee26b1fdd6cd" or
        hash.md5(0, filesize) == "d96b417144fc484cdb1e6430e6884b08" or
        hash.md5(0, filesize) == "0b58f36ecbdaf37a7669a9a52d363849" or
        hash.md5(0, filesize) == "1b41cdb5d2a98222bf33e36255b5169f" or
        hash.md5(0, filesize) == "119856ec134acc86ef76044cbf291f54" or
        hash.md5(0, filesize) == "f8459cec16c4c15d2ea9aee99c398f73" or
        hash.md5(0, filesize) == "9ebd4482171000ba6d4a2da22200c40d" or
        hash.md5(0, filesize) == "e8cd96c3d7f5a99f2ed2c39e23f8355b" or
        hash.md5(0, filesize) == "0d70b3825647082d779987f2772bd219" or
        hash.md5(0, filesize) == "9394e505be0e7a274cd7431abd53aef1" or
        hash.md5(0, filesize) == "c8d43c18b4b451e1722ebb0adbd924b5" or
        hash.md5(0, filesize) == "7ba4c93c6142fd6b1b0c34f92deda07a" or
        hash.md5(0, filesize) == "a74c5f1022edb72d1cb39381664809b5" or
        hash.md5(0, filesize) == "e4814c8dc3d6d83ecb0ed32bf1d6f593" or
        hash.md5(0, filesize) == "daec53d5a033d22b522d9fa3973ece16"
}


rule Qilin_Ransomware_Network_IOC
{
    meta:
        author      = "AnonLabs"
        description = "Detects Qilin ransomware network indicators (domains, IPs, FTP credentials)"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "ransomware"

    strings:
        // Onion addresses
        $onion1 = "ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion" ascii wide
        $onion2 = "ozsxj4hwxub7gio347ac7tyqqozvfioty37skqilzo2oqfs4cw2mgtyd.onion" ascii wide
        $onion3 = "24kckepr3tdbcomkimbov5nqv2alos6vmrmlxdr76lfmkgegukubctyd.onion" ascii wide
        $onion4 = "wlh3dpptx2gt7nsxcor37a3kiyaiy6qwhdv7o6nl6iuniu5ycze5ydid.onion" ascii wide
        $onion5 = "kbsqoivihgdmwczmxkbovk7ss2dcynitwhhfu5yw725dboqo5kthfaad.onion" ascii wide
        
        // Surface domains
        $domain1 = "wikileaks-v2.com" ascii wide
        $domain2 = "wikileaks-v2.net" ascii wide
        $domain3 = "wikileaksv2.com" ascii wide
        $domain4 = "wikileaks2.site" ascii wide
        
        // IP addresses (string format)
        $ip1 = "85.209.11.49" ascii wide
        $ip2 = "176.113.115.97" ascii wide
        $ip3 = "176.113.115.209" ascii wide
        $ip4 = "188.119.66.189" ascii wide
        $ip5 = "185.196.10.52" ascii wide
        $ip6 = "185.196.10.19" ascii wide
        $ip7 = "64.176.162.76" ascii wide
        $ip8 = "31.41.244.100" ascii wide
        $ip9 = "216.158.229.74" ascii wide
        
        // FTP credentials
        $ftp1 = "dataShare:nX4aJxu3rYUMiLjCMtuJYTKS" ascii wide
        $ftp2 = "dataShare:2bTWYKNn7aK7Rqp9mnv3" ascii wide
        $ftp3 = "datashare:ENqh0jBHKia2L22fxzivbhRL" ascii wide
        
        // Hostnames
        $host1 = "WIN-LIVFRVQFMKO" ascii wide
        $host2 = "WIN-8OA3CCQAE4D" ascii wide
        
        // Tox ID
        $tox = "7C35408411AEEBD53CDBCEBAB167D7B22F1E66614E89DFCB62EE835416F60E1BCD6995152B68" ascii wide

    condition:
        any of them
}


rule Qilin_Ransomware_FTP_Communication
{
    meta:
        author      = "AnonLabs"
        description = "Detects Qilin ransomware FTP exfiltration patterns"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "high"
        category    = "ransomware"

    strings:
        $ftp_url1 = "ftp://dataShare:nX4aJxu3rYUMiLjCMtuJYTKS@85.209.11.49" ascii wide
        $ftp_url2 = "ftp://dataShare:nX4aJxu3rYUMiLjCMtuJYTKS@176.113.115.97" ascii wide
        $ftp_url3 = "ftp://dataShare:2bTWYKNn7aK7Rqp9mnv3@176.113.115.209" ascii wide
        $ftp_url4 = "ftp://dataShare:2bTWYKNn7aK7Rqp9mnv3@188.119.66.189" ascii wide
        $ftp_url5 = "ftp://datashare:C}^SLA\"5Vl?vX#R4tg^}hd3@185.196.10.52" ascii wide
        $ftp_url6 = "ftp://datashare:ENqh0jBHKia2L22fxzivbhRL@64.176.162.76" ascii wide
        
        // FTP commands
        $ftp_cmd1 = "STOR" ascii wide
        $ftp_cmd2 = "RETR" ascii wide
        $ftp_cmd3 = "PASV" ascii wide
        
        // ASN references
        $asn1 = "Chang Way Tech" ascii wide
        $asn2 = "Global-Data System IT Corporation" ascii wide
        $asn3 = "AS57678" ascii wide
        $asn4 = "AS42624" ascii wide
        $asn5 = "AS-VULTR" ascii wide

    condition:
        any of ($ftp_url*) or (2 of ($ftp_cmd*) and any of ($asn*))
}


rule Qilin_Ransomware_CobaltStrike_Indicators
{
    meta:
        author      = "AnonLabs"
        description = "Detects Cobalt Strike indicators associated with Qilin ransomware operations"
        date        = "2026-03-01"
        version     = "1.0"
        severity    = "critical"
        category    = "ransomware"

    strings:
        // Cobalt Strike default pipe names
        $pipe1 = "\\\\.\\pipe\\mojo." ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        
        // Cobalt Strike reflective loader
        $s1 = "ReflectiveLoader" ascii wide
        $s2 = "beacon.dll" ascii wide
        $s3 = "beacon.x64.dll" ascii wide
        $s4 = "beacon.x86.dll" ascii wide
        
        // Associated tools
        $tool1 = "Vidar Stealer" ascii wide
        $tool2 = "Lumma Stealer" ascii wide
        $tool3 = "AsyncRAT" ascii wide
        $tool4 = "SystemBC" ascii wide
        $tool5 = "Amadey" ascii wide
        $tool6 = "SliverC2" ascii wide
        
        // Infrastructure references
        $infra1 = "Red Bytes LLC" ascii wide
        $infra2 = "Bearhost" ascii wide

    condition:
        (any of ($pipe*) and any of ($s*)) or (2 of ($tool*) and any of ($infra*))
}