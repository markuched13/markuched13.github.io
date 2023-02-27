### Windows Privilege Escalation

### Cheatsheet

#### Interface(s), IP Address(es), DNS Information

`
C:\Users\HP> ipconfig /all
`

#### ARP Table

`
C:\Users\HP> arp -a
`

#### Routing Table

`
C:\Users\HP> route print
`

#### Check Windows Defender Status

`
PS C:\Users\HP> Get-MpComputerStatus
`

#### Get AppLocker Rules

`
PS C:\Users\HP> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
`

#### Test AppLocker Policy

`
PS C:\Users\HP> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
`

#### Checking Running Processes

`
C:\Users\HP> tasklist /svc
`

#### Get All Environment Variable

`
C:\Users\HP> set
`

#### View Detailed Configuration Information

`
C:\Users\HP> systeminfo
`

#### View Patches and Updates

`
C:\Users\HP> wmic qfe
PS C:\Users\HP>  Get-HotFix | ft -AutoSize
`



