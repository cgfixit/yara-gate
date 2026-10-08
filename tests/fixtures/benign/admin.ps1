Get-Service -Name Spooler | Select-Object Name, Status
Restart-Service -Name Spooler -Confirm:$false
Write-Output "spooler restarted locally"
