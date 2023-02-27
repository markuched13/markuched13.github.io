### Windows Privilege Escalation

### Cheatsheet

#### Interface(s), IP Address(es), DNS Information

`
ipconfig /all
`

#### ARP Table

`
arp -a
`

#### Routing Table

`
route print
`

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

