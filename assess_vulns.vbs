Const forwriting = 2
Const ForAppending = 8
Const ForReading = 1
Dim objFSO: Set objFSO = CreateObject("Scripting.FileSystemObject")

'---config
strDriveLetter = "c" 'change to drive letter of mounted volume to assess
strWindowsDir = "windows" ' "windows.old\windows
'---end config

CurrentDirectory = GetFilePath(wscript.ScriptFullName)

if boolEnableNetAPI32Check = True then DictFeedInfo.Add "MS08-067", "netapi32.dll"
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\syswow64\netapi32.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\syswow64\netapi32.dll", ""), false
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\netapi32.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\netapi32.dll", ""), false

if boolEnableFlashCheck = True then DictFeedInfo.Add "Flash Player", "Flash Player"


if boolEnableMshtmlCheck = True then DictFeedInfo.Add "MS15-065", "mshtml.dll"
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\syswow64\mshtml.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\syswow64\mshtml.dll", "") , false
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\mshtml.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\mshtml.dll", ""), false



if boolEnableSilverlightCheck = True then DictFeedInfo.Add "silverlight", "silverlight"
if boolEnableIexploreCheck = True then DictFeedInfo.Add "iexplore.exe", "iexplore.exe"


'if bool3155533Check = True then DictFeedInfo.Add "MS16-051", "vbscript.dll"
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\vbscript.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\vbscript.dll", ""), false
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + "c:\" & strWindowsDir & "\syswow64\vbscript.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\syswow64\vbscript.dll", ""), false

'if boolMS17010Check = true then DictFeedInfo.Add "MS17-070", "srv.sys"
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\drivers\srv.sys" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\drivers\srv.sys", ""), false


'if boolCVE_2017_11826 = True then DictFeedInfo.Add "Microsoft Word", "winword.exe" 'CVE-2017-11826

'elseif  ((instr(lcase(strVulnPath),":\program files (x86)\microsoft office") > 0 and instr(lcase(strVulnPath), "\office") > 0) or _
'(instr(lcase(strVulnPath),":\program files\microsoft office") > 0 and instr(lcase(strVulnPath), "\office") > 0) or _
'(instr(lcase(strVulnPath),":\program files\windowsapps\microsoft.office.desktop.word_") > 0 and instr(lcase(strVulnPath), "\office") > 0)) and _
'instr(lcase(strVulnPath), "\winword.exe") > 0 and instr(lcase(strVulnPath), "\microsoft office\\updates\\download\") = 0 then

if boolCVE_2019_0708 = True then DictFeedInfo.Add "BlueKeep", "termdd.sys"
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\drivers\termdd.sys" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\drivers\termdd.sys", ""), false


if boolDejaBlue = True then DictFeedInfo.Add "DejaBlue", "termsrv.dll"
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\termsrv.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\termsrv.dll", ""), false



if boolCVE_2020_0601 = True then DictFeedInfo.Add "CVE-2020-0601", "crypt32.dll" 'CVE-2020-0601
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\crypt32.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\crypt32.dll", ""), false
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\syswow64\crypt32.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\syswow64\crypt32.dll", ""), false

'MS15-078
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\system32\lpk.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\system32\lpk.dll", ""), false
logdata CurrentDirectory & "\vuln_assess.log", strDriveLetter + ":\" & strWindowsDir & "\syswow64\lpk.dll" + "," + ParseVulns(strDriveLetter + ":\" & strWindowsDir & "\syswow64\lpk.dll", ""), false


Function AddPipe(strpipeless)
dim strPipeAdded

if len(strpipeless) > 0 then
  if left(strpipeless, 1) <> "|" then 
    strPipeAdded = "|" & replace(strpipeless, "|", ",")

  else
    strPipeAdded = "|" & replace(right(strpipeless, len(strpipeless) -1), "|", ",")
  end if
else
  strPipeAdded = "|"
end if

AddPipe = strPipeAdded 
end function





Function FormatDate(strFDate) 
Dim strTmpMonth
Dim strTmpDay
strTmpMonth = datepart("m",strFDate)
strTmpDay = datepart("d",strFDate)
if len(strTmpMonth) = 1 then strTmpMonth = "0" & strTmpMonth
if len(strTmpDay) = 1 then strTmpDay = "0" & strTmpDay

FormatDate = datepart("yyyy",strFDate) & "-" & strTmpMonth & "-" & strTmpDay


end function

Function ParseVulns(strTmpVulnPath, StrTmpVulnVersion)
if  objfso.fileexists(strTmpVulnPath) = False then 
  ParseVulns = "File does not exist"
  exit function
end if
if StrTmpVulnVersion = "" then
  StrTmpVulnVersion = objfso.GetFileVersion(strTmpVulnPath)
end if
StrVulnVersion = removeInvalidVersion(StrTmpVulnVersion)
strVulnPath = lcase(strTmpVulnPath)
if instr(StrVulnVersion, ".") then
	intWinMajor = left(StrVulnVersion, instr(StrVulnVersion, ".") -1)
	if instr(right(StrVulnVersion, len(StrVulnVersion) - instr(StrVulnVersion, ".")), ".") then
		intWinMinor = left(right(StrVulnVersion, len(StrVulnVersion) - instr(StrVulnVersion, ".")), instr(StrVulnVersion, ".") -1)
	end if
end if
'msgbox "StrVulnVersion=" & StrVulnVersion & "|intWinMajor=" & intWinMajor & "|intWinMinor=" & intWinMinor
'msgbox "strVulnPath=" & strVulnPath
Dim StrVersionCompare
Dim ArrayVulnVer
if instr(lcase(strVulnPath), "\windows\syswow64\macromed\flash\") > 0 or instr(lcase(strVulnPath), "\windows\system32\macromed\flash\") > 0 then
  if instr(lcase(strVulnPath), ".ocx") > 0 or instr(lcase(strVulnPath), ".dll") > 0  or instr(lcase(strVulnPath), ".exe") > 0 then
    'check version number
    if boolDebugFlash = true then msgbox "Flash version assess: " & StrVulnVersion & vbcrlf & _
    "patched version is " & strFlashVersion & vbcrlf & "version patched = " & FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, strFlashVersion)
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, strFlashVersion) = True then
      ParseVulns = "up to date Flash Player detected"
    else 'out of date
      if isnumeric(left(StrVulnVersion, 2)) then
        if left(StrVulnVersion,2) <>  left(strStaticFPversion,2) then
          ParseVulns = "unsupported Flash Player major version detected"
        else
          ParseVulns = "outdated Flash Player version detected"
        end if
      else
        ParseVulns = "outdated Flash Player version detected"
      end if
    end if
  end if
elseif instr(lcase(strVulnPath), "\windows\syswow64\mshtml.dll") > 0 or instr(lcase(strVulnPath), "\windows\system32\mshtml.dll") > 0 then
if instr(strVulnVersion, ".") > 0 then
  ArrayVulnVer = split(strVulnVersion, ".")
  if ubound(ArrayVulnVer) > 2 then
    select case ArrayVulnVer(0)
      Case "6"
      StrVersionCompare = "6.0.3790.5662"
      Case "7"
         if ArrayVulnVer(2) = "6000" then
            StrVersionCompare = "7.0.6000.21481"
        elseif instr(strVulnVersion, "7.0.6002.1") > 0 then
          StrVersionCompare = "7.0.6002.19421"
        else
          StrVersionCompare = "7.0.6002.23728"
        end if
      Case "8"
        if ArrayVulnVer(2) = "6001" then
          if instr(strVulnVersion, "8.0.6001.2") > 0 then
            StrVersionCompare = "8.0.6001.23707"
          else
            StrVersionCompare = "8.0.6001.19652"
          end if
        else
          if instr(strVulnVersion, "8.0.7601.1") > 0 then
            StrVersionCompare = "8.0.7601.18896"
          else
            StrVersionCompare = "8.0.7601.23099"
          end if
        end if
      Case "9"
        if instr(strVulnVersion, "9.0.8112.1") > 0 then
          StrVersionCompare = "9.0.8112.16669"
        else
          StrVersionCompare = "9.0.8112.20784"
        end if
      Case "10"
        if instr(strVulnVersion, "10.0.9200.1") > 0 then
          StrVersionCompare = "10.0.9200.17412"
        else
          StrVersionCompare = "10.0.9200.21523"
        end if
      Case "11"
        if Bool64bit = False then '32-bit version
          StrVersionCompare = "11.0.9600.17905" 'x86
        else
          StrVersionCompare = "11.0.9600.17915" 'x64
        end if
    end select

    if intWinMajor = 5 then
      if intWinMinor = 2 or intWinMinor = 1 then 'windows XP/2003
        ParseVulns = "Unsupported OS Windows XP/2003"
      elseif intWinMinor = 0 then
        ParseVulns = "Unsupported OS Windows 2000"
      end if
    elseif StrVersionCompare <> "" then
      if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
        ParseVulns = "MS15-065 KB3065822 applied"
      else
        ParseVulns = "MS15-065 KB3065822 not applied"
      end if
    end if
  end if
end if
elseif instr(lcase(strVulnPath), "\windows\syswow64\lpk.dll") > 0 or instr(lcase(strVulnPath), "\windows\system32\lpk.dll") > 0 then
  'atm*.dll does not show in all results 
  'so suplimented with lpk.dll which isn't a good indication of being patched for MS15-078 
  'but can indicate a vulnerable system if really outdated
  if intWinMajor = 6 then 
    if intWinMinor = 0 then 
    '6.0.6002.23749 Windows Vista and Windows Server 2008
      if instr(StrVulnVersion, "6.0.6002.1") > 0 then
        if Bool64bit = False then '32-bit version
          StrVersionCompare = "6.0.6002.18051"
        else'64bit version
          StrVersionCompare = "6.0.6002.18005"
        end if
      elseif  instr(StrVulnVersion, "6.0.6001.1") > 0 then
        StrVersionCompare = "6.0.6001.18000"
      else
        StrVersionCompare = "6.0.6002.23749"
      end if
    
    elseif intWinMinor = 1 then 
      '6.1.7601.23126 Windows 7 and Windows Server 2008 R2
      if instr(StrVulnVersion, "6.1.7601.2") > 0 then
        StrVersionCompare = "6.1.7601.23126"
      else
        StrVersionCompare = "6.1.7601.18923"
      end if
    elseif intWinMinor = 2 then 
      '6.2.9200.16384 Windows 8 and Windows Server 2012
      StrVersionCompare = "6.2.9200.16384"
    elseif intWinMinor = 3 then 
      '6.3.9600.17415 Windows 8.1 and Windows Server 2012 R2
      StrVersionCompare = "6.3.9600.17415"
    end if
    
    
    if instr(strVulnVersion, "6.1.7600.") > 0 then
      ParseVulns = "Unsupported OS. Missing Windows 7 SP1"
    elseif StrVersionCompare <> "" then
      if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
            'System may still be vulnerable so don't return anything
            'ParseVulns = "MS15-078 KB3079904 applied"
      else
        ParseVulns = "MS15-078 KB3079904 not applied"
      end if
    end if
  end if
elseif instr(lcase(strVulnPath), "\windows\syswow64\netapi32.dll") > 0 or instr(lcase(strVulnPath), "\windows\system32\netapi32.dll") > 0 then

  if intWinMajor = 5 then
    if intWinMinor = 0 then 'windows 2000
      StrVersionCompare = "5.0.2195.7203"

    elseif intWinMinor = 1 Then
      if instr(StrVulnVersion, "5.1.2600.3") > 0 then
        StrVersionCompare = "5.1.2600.3462"
      else
        StrVersionCompare = "5.1.2600.5694"
      end if
    elseif intWinBuild = 2 then 'windows XP/2003
       if instr(StrVulnVersion, "5.2.3790.3") > 0 then
          StrVersionCompare = "5.2.3790.3229"
       else
          StrVersionCompare = "5.2.3790.4392"
       end if
    end if
  elseif  intWinMajor = 6 then 
    if intWinMinor = 0 then 'windows vista/2008
      if intWinBuild = 6000 then 'sp0
       if instr(StrVulnVersion, "6.0.6000.16") > 0 then
          StrVersionCompare = "6.0.6000.16764"
       else
          StrVersionCompare = "6.0.6000.20937"
       end if      
      elseif intWinBuild = 6001 then 'sp0
       if instr(StrVulnVersion, "6.0.6000.18") > 0 then
          StrVersionCompare = "6.0.6001.18157"
       else
          StrVersionCompare = "6.0.6001.18157"
       end if      
      end if
    end if
  end if
  if StrVersionCompare <> "" then
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "MS08-067 applied"
    else
      ParseVulns = "MS08-067 not installed"
    end if
  end if
elseif instr(lcase(strVulnPath), "\microsoft silverlight\") > 0 and _
instr(lcase(strVulnPath), "\silverlight.configuration.exe") > 0 and instr(lcase(strVulnPath), "\program files") > 0 then
  StrVersionCompare = "5.1.41212.0"
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Silverlight patched with MS16-006 critical bulletin"
    else
      ParseVulns = "Silverlight flaw, identified as CVE-2016-0034, patched under MS16-006 critical bulletin is missing"
    end if
elseif instr(lcase(strVulnPath), "\internet explorer\iexplore.exe") > 0 and instr(lcase(strVulnPath), "\program files") > 0 then
	StrVersionCompare = "11"
	
	if instr(lcase(StrTmpVulnVersion), "vista") > 0 or instr(lcase(StrTmpVulnVersion), "longhorn") > 0 then 'either Vista and server 2008
		StrVersionCompare = "9"
	elseif instr(lcase(StrTmpVulnVersion), "win8") > 0 then 'either server 2012 or Windows 8
		StrVersionCompare = "10"
	end if
	
	if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
		ParseVulns = "IE on a supported version"

	else
		ParseVulns = "Internet Explorer (IE) is at a version that may not receive publicly released security updates. IE version 11 is the only version still receiving updates for Windows 7/Windows Server 2008 R2 and most newer operating systems."
	end if
elseif instr(lcase(strVulnPath), "\vbscript.dll") > 0 and instr(lcase(strVulnPath), "\windows") > 0 and instr(lcase(strVulnPath), "\winsxs\") = 0 then
    'Internet Explorer 9 on all supported x86-based versions of Windows Vista and Windows Server 2008
    if instr(StrVulnVersion, "5.8.7601.1") > 0 then
      StrVersionCompare = "5.8.7601.17295"

    elseif instr(StrVulnVersion, "5.8.7601.2") > 0 then
      ''nternet Explorer 9 on all supported x64-based versions of Windows Vista and Windows Server 2008

        StrVersionCompare = "5.8.7601.20906"
    'Internet Explorer 10 on all supported x64-based versions of Windows Server 201
    elseif instr(StrVulnVersion, "5.8.9200.2") > 0 then
      StrVersionCompare = "5.8.9200.21841"
    'Internet Explorer 11 on all supported Windows RT 8.1 & Internet Explorer 11 on all supported x86-based versions of Windows 8.1 & Internet Explorer 11 on all supported x64-based versions of Windows 8.1 and Windows Server 2012 R2
    elseif instr(StrVulnVersion, "5.8.9600.1") > 0 then
      StrVersionCompare = "5.8.9600.18321"      
    'disabling the following to prevent false-reporting on vulnerable versions (have to go with the higher version number above)
    'Windows 7 and Windows Server 2008 R2 & Internet Explorer 11 on all supported x64-based versions of Windows 7 and Windows Server 2008 R2
    'elseif instr(StrVulnVersion, "5.8.9600.1") then
    '  StrVersionCompare = "5.8.9600.18315" 
    end if
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Internet Explorer patched with MS16-051 KB3155533"
    else
      ParseVulns = "Internet Explorer missing patch released under MS16-051 KB3155533"
    end if
elseif lcase(strVulnPath) = "\windows\system32\drivers\srv.sys" then

	if instr(StrVulnVersion, "6.1.7601.") > 0 then
		  StrVersionCompare = "6.1.7601.23689" '6.1.7601.23689 Win7/Server2008R2 x64/ia-64/x86
    elseif instr(StrVulnVersion, "6.1.7600.") > 0 then
		ParseVulns = "Windows missing patch released under MS17-010 KB4013389" 'no SP1 for Windows 7
		exit function
	elseif instr(StrVulnVersion, "6.0.6002.19") > 0 then
		StrVersionCompare = "6.0.6002.19743"  '6.0.6002.19743 vista/2008 x64
    elseif instr(StrVulnVersion, "6.0.6000.") > 0 then
		ParseVulns = "Windows missing patch released under MS17-010 KB4013389"
		exit function
	elseif instr(StrVulnVersion, "6.0.6002.2") > 0 then
		StrVersionCompare = "6.0.6002.24067"  '6.0.6002.24067 vista/2008 x86
    elseif instr(StrVulnVersion, "6.2.9200.") > 0 then
		StrVersionCompare = "6.2.9200.22099"  'Server 2012		
	elseif instr(StrVulnVersion, "6.3.9600.") > 0 then
		StrVersionCompare = "6.3.9600.18604"  '6.3.9600.18604 Win8.1/rt/Server2012r2 x64/x86		
    elseif instr(StrVulnVersion, "10.0.14393.") > 0 then
		StrVersionCompare = "10.0.14393.953"  '10.0.14393.953 win10
	end if
    if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Windows has been patched for MS17-010 KB4013389"
    else
      ParseVulns = "Windows missing patch released under MS17-010 KB4013389"
    end if
elseif  ((instr(lcase(strVulnPath),":\program files (x86)\microsoft office") > 0 and instr(lcase(strVulnPath), "\office") > 0) or _
(instr(lcase(strVulnPath),":\program files\microsoft office") > 0 and instr(lcase(strVulnPath), "\office") > 0) or _
(instr(lcase(strVulnPath),":\program files\windowsapps\microsoft.office.desktop.word_") > 0 and instr(lcase(strVulnPath), "\office") > 0)) and _
instr(lcase(strVulnPath), "\winword.exe") > 0 and instr(lcase(strVulnPath), "\microsoft office\\updates\\download\") = 0 then
	if instr(StrVulnVersion, "12.0.") > 0 then
		StrVersionCompare = "12.0.6779.5000" 
	elseif instr(StrVulnVersion, "14.0.") > 0 then
		StrVersionCompare = "14.0.7189.5001" 
	elseif instr(StrVulnVersion, "15.0.") > 0 then
		StrVersionCompare = "15.0.4971.1002" 
	elseif instr(StrVulnVersion, "16.0.") > 0 then
		StrVersionCompare = "16.0.4600.1002" 
	end if
	if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Windows has been patched for CVE-2017-11826"
    else
      ParseVulns = "Windows missing patch released for CVE-2017-11826"
    end if
elseif instr(lcase(strVulnPath), "termdd.sys") > 0 then
	'CVE-2019-0708
	'https://support.microsoft.com/en-us/help/4500331/windows-update-kb4500331
	if instr(StrVulnVersion, "5.1.2600") > 0 then 'x86 Win XP
		StrVersionCompare = "5.1.2600.7701" 
	elseif instr(StrVulnVersion, "5.2.3790") > 0 then 'Windows Server 2003
		StrVersionCompare = "5.2.3790.6787"
	elseif instr(StrVulnVersion, "6.0.6003") > 0 then 'vista and server 2008 KB4499180
		StrVersionCompare = "6.0.6003.20514"
	elseif FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, "6.1.0000.00000") then 'unaffected new OS
		ParseVulns = "Windows version unaffected by bluekeep vulnerability"
		Exit function
	end if
	'dejablue
	'elseif instr(StrVulnVersion, "6.1.7601") > 0 then 'Win7 server 2008 R2 KB4512506 going to use termsrv.dll for this
	'	StrVersionCompare = "6.1.7601.24441"
	'elseif
	if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Windows has been patched for CVE-2019-0708 KB4500331"
    else
      ParseVulns = "Windows missing patch released under KB4500331 CVE-2019-0708"
    end if
elseif instr(lcase(strVulnPath), "termsrv.dll") > 0 then 'dejablue
	if FirstVersionSupOrEqualToSecondVersion("6.0.9999.99999", StrVulnVersion) Then 'unaffected older OS
		ParseVulns = "Windows version unaffected by dejablue vulnerabilities"
		Exit function
	elseif instr(StrVulnVersion, "6.1.7601.") > 0 Or instr(StrVulnVersion, "6.1.7600.") > 0 then 'Win7 server 2008 R2 KB4512506
		StrVersionCompare = "6.1.7601.24402"
	elseif instr(StrVulnVersion, "6.2.9200.") > 0 then 'KB4512518 server 2018
		StrVersionCompare = "6.2.9200.22715"	
	elseif instr(StrVulnVersion, "6.3.9600.") > 0 then 'KB4512488 ARM Windows RT 8.1
		StrVersionCompare = "6.3.9600.19318"
	elseif instr(StrVulnVersion, "10.0.10240.") > 0 then 'KB4512497
		StrVersionCompare = "10.0.10240.18186"
	elseif instr(StrVulnVersion, "10.0.14393.") > 0 then 'KB4512517 
		StrVersionCompare = "10.0.14393.2906"		
	elseif instr(StrVulnVersion, "10.0.15063.") > 0 then 'KB4512507 
		StrVersionCompare = "10.0.15063.1746"			
	elseif instr(StrVulnVersion, "10.0.16299.") > 0 then 'KB4512516 
		StrVersionCompare = "10.0.16299.15"		
	elseif instr(StrVulnVersion, "10.0.17134.") > 0 then 'KB4512501 (1803)
		StrVersionCompare = "10.0.17134.706"	
	elseif instr(StrVulnVersion, "10.0.17763.") > 0 then 'KB missing version number (1809)
		StrVersionCompare = "10.0.17763.678" 
	elseif instr(StrVulnVersion, "10.0.18362.") > 0 then 'KB4512501 (1903)
		StrVersionCompare = "10.0.18362.295"		
	end if
	if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Windows has been patched for dejablue vulnerabilities"
    else
      ParseVulns = "Windows missing patch for dejablue vulnerabilities"
    end if
elseif instr(lcase(strVulnPath), "crypt32.dll") > 0 then 'CVE-2020-0601 
	if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, "10") = False then 'only Windows 10/2016 or greater are vulnerable
    ParseVulns = "Windows version unaffected by CVE-2020-0601 vulnerability"
		Exit function
	elseif instr(StrVulnVersion, "10.0.10240.") > 0 then 'KB4534306 (Windows 10)
		StrVersionCompare = "10.0.10240.18186"
	elseif instr(StrVulnVersion, "10.0.14393.") > 0 then 'KB4534271 (Windows 10, version 1607 Windows Server 2016) 
		StrVersionCompare = "10.0.14393.3442"
	elseif instr(StrVulnVersion, "10.0.16299.") > 0 then 'KB4534276 (Windows 10, version 1709) 
		StrVersionCompare = "10.0.16299.1622"
	elseif instr(StrVulnVersion, "10.0.17134.") > 0 then 'KB4534293 (Windows 10, version 1803)
		StrVersionCompare = "10.0.17134.1246"
	elseif instr(StrVulnVersion, "10.0.17763.") > 0 then 'KB4534273 (Windows 10, version 1809 Windows Server version 1809 Windows Server 2019, all versions)
		StrVersionCompare = "10.0.17763.678"
	elseif instr(StrVulnVersion, "10.0.18362.") > 0 then 'KB4528760 (Windows 10, version 1903 Windows Server version 1903)
		StrVersionCompare = "10.0.18362.592"
	elseif instr(StrVulnVersion, "10.0.1909.") > 0 then 'KB4528760 (Windows 10, version 1909)
		StrVersionCompare = "10.0.1909.592"
	end if
	if StrVersionCompare = "" then
    if UnsupportedWin10(StrVulnVersion) = True then
      ParseVulns = "Windows missing patch for CVE-2020-0601 vulnerability due to unsupported build version"
      Exit function
    end if
	end if
	if FirstVersionSupOrEqualToSecondVersion(StrVulnVersion, StrVersionCompare) then
      ParseVulns = "Windows has been patched for CVE-2020-0601 vulnerability"
    else
      ParseVulns = "Windows missing patch for CVE-2020-0601 vulnerability"
    end if
end if
end function

Function UnsupportedWin10(strWin10Version)
boolVersionUnsupported = False
select case left(strWin10Version, 10)
  case "10.0.10240"
    boolVersionUnsupported = True
  case "10.0.10586"
    boolVersionUnsupported = True
  case "10.0.14393"
    boolVersionUnsupported = True
  case "10.0.15063"
    boolVersionUnsupported = True
  case "10.0.16299"
    boolVersionUnsupported = True
  case "10.0.17134"
    boolVersionUnsupported = True
  case "10.0.18362"
    boolVersionUnsupported = True
end select
UnsupportedWin10 = boolVersionUnsupported
end function

Function removeInvalidVersion(strVersionNumber)
Dim StrReturnValidVersion

if instr(strVersionNumber, " ") > 0 then
    StrReturnValidVersion = left(strVersionNumber, instr(strVersionNumber, " "))
else
  StrReturnValidVersion = strVersionNumber
end if
if instr(StrReturnValidVersion, ",") > 0 then
  StrReturnValidVersion = replace(StrReturnValidVersion, ",", ".")
end if
removeInvalidVersion = StrReturnValidVersion
end function

Function FirstVersionSupOrEqualToSecondVersion(strTmpFirstVersion, strTmpSecondVersion)
StrTmpVersionNumber = removeInvalidVersion(strTmpFirstVersion)	
strFirstVersion = StrTmpVersionNumber
StrTmpVersionNumber = removeInvalidVersion(strTmpSecondVersion)	
strSecondVersion = StrTmpVersionNumber
if boolDebugVersionCompare = True then msgbox "version compare " & strFirstVersion & vbcrlf & strSecondVersion
Dim arrFirstVersion,  arrSecondVersion, i, iStop, iMax
Dim iFirstArraySize, iSecondArraySize
Dim blnArraySameSize : blnArraySameSize = False

If strFirstVersion = strSecondVersion Then
  FirstVersionSupOrEqualToSecondVersion = True
  Exit Function
End If

If strFirstVersion = "" Then
  FirstVersionSupOrEqualToSecondVersion = False
  Exit Function
End If
If strSecondVersion = "" Then
  FirstVersionSupOrEqualToSecondVersion = True
  Exit Function
End If
if isnumeric(replace(strFirstVersion, ".", "")) = false then
  msgbox "Error converting version number due to non numeric value in the fist listed version: " & strFirstVersion
  exit function
end if
if isnumeric(replace(strSecondVersion, ".", "")) = false then
  msgbox "Error converting version number due to non numeric value in the second listed version: " & strSecondVersion
  exit function
end if
arrFirstVersion = Split(strFirstVersion, "." )
arrSecondVersion = Split(strSecondVersion, "." )
iFirstArraySize = UBound(arrFirstVersion)
iSecondArraySize = UBound(arrSecondVersion)

If iFirstArraySize = iSecondArraySize Then
  blnArraySameSize = True
  iStop = iFirstArraySize
  For i=0 To iStop
    'msgbox "arrFirstVersion=" & arrFirstVersion(i) & vbcrlf & "arrSecondVersion=" & arrSecondVersion(i)
    If clng(arrFirstVersion(i)) < clng(arrSecondVersion(i)) Then
      FirstVersionSupOrEqualToSecondVersion = False
      Exit Function
    elseif clng(arrFirstVersion(i)) > clng(arrSecondVersion(i)) then
      FirstVersionSupOrEqualToSecondVersion = True
      Exit Function			
    End If
  Next
  FirstVersionSupOrEqualToSecondVersion = True
Else
  If iFirstArraySize > iSecondArraySize Then
    iStop = iSecondArraySize
  Else
    iStop = iFirstArraySize
  End If
  For i=0 To iStop
    If clng(arrFirstVersion(i)) < clng(arrSecondVersion(i)) Then
      FirstVersionSupOrEqualToSecondVersion = False
      Exit Function
    elseif clng(arrFirstVersion(i)) > clng(arrSecondVersion(i)) then
      FirstVersionSupOrEqualToSecondVersion = True
      Exit Function			
    End If
  Next
  If iFirstArraySize > iSecondArraySize Then
    FirstVersionSupOrEqualToSecondVersion = True
    Exit Function
  Else
    For i=iStop+1 To iSecondArraySize
      If clng(arrSecondVersion(i)) > 0 Then
        FirstVersionSupOrEqualToSecondVersion = False
        Exit Function
      End If
    Next
    FirstVersionSupOrEqualToSecondVersion = True
  End If
End If
End Function

function LogData(TextFileName, TextToWrite,EchoOn)
Set fsoLogData = CreateObject("Scripting.FileSystemObject")
if EchoOn = True then wscript.echo TextToWrite
  If fsoLogData.fileexists(TextFileName) = False Then
      'Creates a replacement text file 
      on error resume next
      fsoLogData.CreateTextFile TextFileName, True
      if err.number <> 0 and err.number <> 53 then msgbox "Logging error: " & err.number & " " & err.description & vbcrlf & TextFileName
      on error goto 0
  End If
if TextFileName <> "" then


  Set WriteTextFile = fsoLogData.OpenTextFile(TextFileName,ForAppending, False)
  on error resume next
  WriteTextFile.WriteLine TextToWrite
  if err.number <> 0 then 
    on error goto 0
    WriteTextFile.Close
  Dim objStream
  Set objStream = CreateObject("ADODB.Stream")
  objStream.CharSet = "utf-16"
  objStream.Open
  objStream.WriteText TextToWrite
  on error resume next
  objStream.SaveToFile TextFileName, 2
  if err.number <> 0 then msgbox err.number & " - " & err.message & " Problem writting to " & TextFileName
  if err.number <> 0 then msgbox "problem writting text: " & TextToWrite
  on error goto 0
  Set objStream = nothing
  end if
end if
Set fsoLogData = Nothing
End Function

Function GetFilePath (ByVal FilePathName)
found = False

Z = 1
Do While found = False and Z < Len((FilePathName))

 Z = Z + 1
       If InStr(Right((FilePathName), Z), "\") <> 0 And found = False Then
          mytempdata = Left(FilePathName, Len(FilePathName) - Z)
          GetFilePath = mytempdata
          found = True
       End If      
Loop
end Function