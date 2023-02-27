### Windows Privilege Escalation

### Cheatsheet

#### Check Windows Defender Status

`
PS C:\Users\HP> Get-MpComputerStatus
`

#### Get AppLocker Rules

`
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
`

#### Test AppLocker Policy

`
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
`

