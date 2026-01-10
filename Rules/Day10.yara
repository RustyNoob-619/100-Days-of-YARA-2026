import "pe"
  
rule Actor_APT_DPRK_Multiple_MAL_WIN_DLL_RAT_NukeSped64_PEProperties_Jan26
{
    meta:
        rule_id = "df2fbbbe-9740-433d-ba15-4410fa0325eb"
        date = "10-01-2026"
        author = "Rustynoob619"
        description = "Detects NukeSped used by various DPRK APTs based on PE Rich header properties"
        source = "https://www.fortinet.com/blog/threat-research/deep-analysis-nukesped-rat"
        filehash = "ff2eb800ff16745fc13c216ff6d5cc2de99466244393f67ab6ea6f8189ae01dd"

    condition:
        uint16(0) == 0x5a4d
        and pe.rich_signature.length > 0
        and pe.rich_signature.version(21005) > 0
        and pe.exports("ExtractMicrosoftWord")
        and filesize < 500KB
}
