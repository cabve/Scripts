<#
    .DESCRIPTION 
    *Work In Progress*
    Get Burp extensions, script for getting usable burp extensions.
    Author: caabv
#>

$i = 0
if (Test-Path "C:\Temp\Burp") {
	Write-Host "C:\Temp\Burp - exist" -ForegroundColor Yellow; $i = 1
}
else {
	New-Item -ItemType directory -Path 'C:\Temp\Burp'
	Write-Host "Created 'Burp' folder in 'C:\Temp\'" -ForegroundColor Yellow
}

Invoke-WebRequest -Uri 'https://github.com/albinowax/ActiveScanPlusPlus/archive/master.zip' -OutFile 'C:\TEMP\Burp\ActiveScanPlusPlus.zip'

Invoke-WebRequest -Uri 'https://github.com/RetireJS/retire.js/archive/master.zip' -OutFile 'C:\Temp\Burp\retirejs.zip'

Invoke-WebRequest -Uri 'https://github.com/NetSPI/JSONBeautifier/archive/master.zip' -OutFile 'C:\Temp\Burp\JSONBeautifier.zip'

Invoke-WebRequest -Uri 'https://github.com/federicodotta/Java-Deserialization-Scanner/archive/master.zip' -OutFile 'C:\Temp\Burp\Java-Deserialization-Scanner.zip'

Invoke-WebRequest -Uri 'https://github.com/allfro/dotNetBeautifier/archive/master.zip' -OutFile 'C:\Temp\Burp\dotNetNeautifier.zip'

Invoke-WebRequest -Uri 'https://github.com/NetSPI/JavaSerialKiller/archive/master.zip' -OutFile 'C:\Temp\Burp\JavaSerialKiller.zip'

Invoke-WebRequest -Uri 'https://github.com/lightbulb-framework/lightbulb-framework/archive/master.zip' -OutFile 'C:\Temp\Burp\Lightbulb.zip'

Invoke-WebRequest -Uri 'https://github.com/PortSwigger/additional-scanner-checks/archive/master.zip' -OutFile 'C:\Temp\Burp\AdditionalScannerChecks.zip'

Invoke-WebRequest -Uri 'https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/archive/master.zip' -OutFile 'C:\Temp\Burp\Logger.zip'

Invoke-WebRequest -Uri 'https://github.com/PortSwigger/custom-parameter-handler/archive/master.zip' -OutFile 'C:\Temp\Burp\custom-paramter-handler.zip'

Invoke-WebRequest -Uri 'https://github.com/PortSwigger/match-replace-session-action/archive/master.zip' -OutFile 'C:\Temp\Burp\match-replace-session.zip'

Invoke-WebRequest -Uri 'https://github.com/NetSPI/Wsdler/archive/master.zip' -OutFile 'C:\Temp\Burp\Wsdler.zip'

Invoke-WebRequest -Uri 'https://github.com/PortSwigger/collaborator-everywhere/archive/master.zip' -OutFile 'C:\Temp\Burp\collaborator-everywhere.zip'

Invoke-WebRequest -Uri 'https://github.com/PortSwigger/software-vulnerability-scanner/archive/master.zip' -OutFile 'C:\Temp\Burp\software-vuln-scanner.zip'

Invoke-WebRequest -Uri 'https://github.com/AresS31/swurg/archive/master.zip' -OutFile 'C:\Temp\Burp\swaggerParser.zip'

Invoke-WebRequest -Uri 'https://github.com/codewatchorg/sqlipy/archive/master.zip' -OutFile 'C:\Temp\Burp\sqlipy.zip'

Invoke-WebRequest -Uri 'https://github.com/PortSwigger/content-type-converter/archive/master.zip' -OutFile 'C:\Temp\Burp\contentTypeConverter.zip'

Invoke-WebRequest -Uri 'https://gitlab.com/technotame/cookie-decrypter/-/archive/master/cookie-decrypter-master.zip' -OutFile 'C:\Temp\Burp\CookieDecrypter.zip'

Invoke-WebRequest -Uri 'https://github.com/PortSwigger/backslash-powered-scanner/archive/master.zip' -OutFile 'C:\Temp\Burp\backslashPoweredScanner.zip'

Write-Host "Downloaded all extensions - starting to unzip" -ForegroundColor Yellow

Get-ChildItem 'C:\Temp\Burp\' -Filter *.zip | Expand-Archive -DestinationPath 'C:\Temp\Burp\' -Force

Write-Host "All .zip files unzipped" -ForegroundColor Yellow

Write-Host "Cleaning up" -ForegroundColor Yellow

Remove-Item -Path 'C:\Temp\Burp\*.zip'

Write-Host "Script finished" -ForegroundColor Green
