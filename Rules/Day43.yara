import "pe"

rule Actor_APT_CN_MustangPanda_MAL_WIN_SYS_Rootkit_Unknown_Dec25
{
    meta:
        rule_id = "778bc752-9e80-4a7e-832b-10f54d4e5c5d"
        date = "30-12-2025" 
        author = "Rustynoob619"
        description = "Detects rootkit derived from the used by Chinese APT Mustang Panda leading to execution of Tone Shell backdoor based on observed characteristics from the report"
        note = "look for a .SYS file with name ProjectConfiguration (alt. AppvVStram_.sys) signed by Guangzhou Kingteller Technology Co., Ltd. with size around 61KB"
        source = "https://securelist.com/honeymyte-kernel-mode-rootkit/118590/"
        filehash = "859db05738c5692a0522e1a392b027fa40b4e429093c6cd66b60fe7b23ab5199"
        //Xi’an Diwei Digital Technology Co., Ltd 5A EB 0F F1 F0 21 35 AA 58 C4 38 66 94 31 B1 2F
        

    strings:
        $str1 = "FSFilter Anti-Virus" ascii wide
        $str2 = "WdFilter" ascii wide
        $str3 = "SeLocalSystemSid" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and pe.imports("FLTMGR.SYS","FltRegisterFilter")
        and pe.imports("ntoskrnl.exe","ZwQueryInformationProcess")
        and pe.imports("ntoskrnl.exe","CmRegisterCallbackEx")
        and pe.imports("ntoskrnl.exe","ObRegisterCallbacks")
        and pe.imports("ntoskrnl.exe","PsSetCreateProcessNotifyRoutine")
        //and pe.is_signed 
        //and not pe.signatures[0].valid_on(pe.timestamp)
        //pe.pdb_path == "E:\\x64\\Release\\SelfDriver.pdb" Check other files with this PDB
        and any of them
        and filesize < 100KB
}
