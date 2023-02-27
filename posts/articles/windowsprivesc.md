### Windows Privilege Escalation

### Cheatsheet

#### Interface(s), IP Address(es), DNS Information

```
C:\Users\HP> ipconfig /all
```

#### ARP Table

```
C:\Users\HP> arp -a
```

#### Routing Table

```
C:\Users\HP> route print
```

#### Check Windows Defender Status

```
PS C:\Users\HP> Get-MpComputerStatus
```

#### Get AppLocker Rules

```
PS C:\Users\HP> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

#### Test AppLocker Policy

```
PS C:\Users\HP> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

#### Checking Running Processes

```
C:\Users\HP> tasklist /svc
```

#### Get All Environment Variable

```
C:\Users\HP> set
```

#### View Detailed Configuration Information

```
C:\Users\HP> systeminfo
```

#### View Patches and Updates

```
C:\Users\HP> wmic qfe

PS C:\Users\HP>  Get-HotFix | ft -AutoSize
```

#### Get The List Of Installed Programs

```
C:\Users\HP> wmic product get name

PS C:\Users\HP> Get-WmiObject -Class Win32_Product |  select Name, Version
```

#### Display Running Processes

```
C:\Users\HP> netstat -ano
```

#### Logged-In Users

```
C:\Users\HP> query user

C:\Users\HP> qwinsta
```

#### Current User

```
C:\Users\HP> echo %USERNAME%

C:\Users\HP> whoami
```

#### Current User Privileges

```
C:\Users\HP> whoami /priv
```

#### Current User Group Information

```
C:\Users\HP> whoami /groups
```

#### Get All Users

```
C:\Users\HP> net user
```

#### Get All Groups

```
C:\Users\HP> net localgroup
```

#### Details About a Group

```
C:\Users\HP> net localgroup administrators
```

#### Get Password Policy & Other Account Information

```
C:\Users\HP> net accounts
```







#### Resources
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
[HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
[IredTeam](https://www.ired.team/offensive-security/)
