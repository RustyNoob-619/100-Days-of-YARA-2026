
import "pe"

rule SUS_WIN_PE_ImportsNumRichSigProdIdImport0_Mismatch_Version_PE_Properties_Jan26
{
    meta:
        rule_id = "b623b3f8-5e4f-41d8-8f17-1ec51f07173c"
        date = "06-01-2026"
        author = "Rustynoob619"
        description = "Detects Windows PE files where there is a mismatch between the number of PE imports and the ProdIDImport0 tool id count which also indicates the number of PE imports"
        source = "https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/"

    condition:
        uint16(0) == 0x5A4D 
        and pe.rich_signature.toolid(0) > 0
        and (pe.number_of_imports - pe.rich_signature.toolid(1)) > 20
        and filesize < 10MB

}

/* 
Known FPs 
02684651918b548302cf3ed015a2c1442a28f74bc02ce9bdb616c2fd6c4a990d
472a2c44b9ac74acfcf7f2adfdafae35988aa8b4f5c93dd5a8d3f902dc83fd32
69fd140e9c04cac051f8f592fbb2884bd9b15cc2e0820917a8d0f2bdf05b6425
b47f12d118c75c710a5c1fcae47384c8189ff6019cead69e6a3d1a11ab1ebdf4
ab2d6ffb7bada1dfecd2ab2e421ac739ffb5a653fcab17bdbe67d9f255bd53a6
987ca9648a3733e282eea0988ca1d3a8fc789f5073e376b26c226bdbbb2003ac
ef1f497b250409da8306884c0f4453fcff427bc24de8c4e82fc8710723a8ec5c
30ddda0c43df71d3015bbd1fde6d49afaa507d7852a502b00422fcecacf46ba2
bfeba2fcea9caf362e01f404eb2932934de2c931f6516c57173cda31fe3d5ec9
*/







