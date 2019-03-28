<#
.DESCRIPTION
   Test script
.EXAMPLE
   Get-Content -Path Computers.txt | Test-Connectivity
#>
function Test-Connectivity
{
    [CmdletBinding()]
    Param
	(
        [Parameter(ValueFromPipeline)]
        $ComputerName
    )
    Process
	{
        if ((Test-Connection -ComputerName $ComputerName -Quiet -Count 1) -and (Test-Path -Path "\\$ComputerName\c$")
        {
            $true
        }
		else
		{
			$false
		}
    }
}
