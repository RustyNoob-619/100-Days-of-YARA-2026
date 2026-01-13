import "pe"

rule Actor_APT_WesternAsia_UNG0801_MAL_WIN_EXE_Loader_Unknown_PEProperties_Jan26
{
    meta:
        rule_id = "ed32465e-5ab3-4a1c-be09-0aacbd24937d"
        date = "13-01-2026"
        author = "Rustynoob619"
        description = "Detects Malware used by UNG0801 based on PE import hash"
        source = "https://malware.news/t/ung0801-tracking-threat-clusters-obsessed-with-av-icon-spoofing-targeting-israel/102767"
        filehash = "54ebdea80d30660f1d7be0b71bc3eb04189ef2036cdbba24d60f474547d3516a"

    condition:
        uint16(0) == 0x5a4d 
        and pe.imphash() == "5f063da3a76fd3b8a02dfca75a32d59b"
        and filesize < 2MB

}
