### Lame HTB

### IP Address = 10.10.10.226

### Difficulty = Easy

Nmap Scan: 

```                                                                                                     
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/ScriptKiddie]
└─$ nmap -sCV -A 10.10.10.226 -p22,5000 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-18 14:55 WAT
Nmap scan report for 10.10.10.226
Host is up (0.30s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.16 seconds
```

Web page:
![image](https://user-images.githubusercontent.com/113513376/213191746-5655ea76-3233-4880-bfcd-703cc1e3b959.png)

Gobuster didn't return any result 
![image](https://user-images.githubusercontent.com/113513376/213192989-bc2d73dd-79b6-4909-b8b2-e5a56df1c3ee.png)

Checking the tcp port scanner from the web page shows it indeeds work
![image](https://user-images.githubusercontent.com/113513376/213192689-f8ddb4dd-eeaa-4586-9028-dfebd32c830a.png)

Trying to tamper with the search functions but its not vulnerable to command injection
![image](https://user-images.githubusercontent.com/113513376/213194679-ff539e11-73f4-463f-83ac-6b784730ab5f.png)

Creating a binary using the msfvenom function. It works also  
![image](https://user-images.githubusercontent.com/113513376/213195722-14a80aa9-7f39-4fb1-acde-a3c4135f3209.png)

Since we can create a binary which means there's metasploit in the box 

Using the searchsploit function i can attempt to exploit the msfvenom in the box

So I searched for `msfvenom`

Result shows that there's a version of msfvenom which is vulnerable to command injection 
```                                                                                                     
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/ScriptKiddie]
└─$ searchsploit msfvenom                  
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Metasploit Framework 6.0.11 - msfvenom APK template command injection | multiple/local/49491.py
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

So on checking metasploit there's also an exploit for it i'ma use metasploit to test it xD
```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/ScriptKiddie]
└─$ msfconsole 
msf6 > 
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMM                MMMMMMMMMM
MMMN$                           vMMMM
MMMNl  MMMMM             MMMMM  JMMMM
MMMNl  MMMMMMMN       NMMMMMMM  JMMMM
MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM
MMMNI  WMMMM   MMMMMMM   MMMM#  JMMMM
MMMMR  ?MMNM             MMMMM .dMMMM
MMMMNm `?MMM             MMMM` dMMMMM
MMMMMMN  ?MM             MM?  NMMMMMN
MMMMMMMMNe                 JMMMMMNMMM
MMMMMMMMMMNm,            eMMMMMNMMNMM
MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM
MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM
        https://metasploit.com


       =[ metasploit v6.2.9-dev                           ]
+ -- --=[ 2229 exploits - 1177 auxiliary - 398 post       ]
+ -- --=[ 867 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: When in a module, use back to go 
back to the top level prompt

msf6 > search msfvenom

Matching Modules
================

   #  Name                                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                                    ---------------  ----       -----  -----------
   0  exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection  2020-10-29       excellent  No     Rapid7 Metasploit Framework msfvenom APK Template Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
```

So let me try it out
![image](https://user-images.githubusercontent.com/113513376/213199092-ee312adf-05f9-499c-a168-65120bbbf2bf.png)

On running it the payload doesn't generate 
![image](https://user-images.githubusercontent.com/113513376/213199478-82170aaf-cc33-4854-8af7-badce542b220.png)

Trying out other payloads
```
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > search payloads

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   exploit/unix/webapp/awstats_migrate_exec                    2006-05-04       excellent  Yes    AWStats migrate Remote Command Execution
   1   exploit/linux/http/alcatel_omnipcx_mastercgi_exec           2007-09-09       manual     No     Alcatel-Lucent OmniPCX Enterprise masterCGI Arbitrary Command Execution
   2   encoder/x86/alpha_mixed                                                      low        No     Alpha2 Alphanumeric Mixedcase Encoder
   3   encoder/x86/alpha_upper                                                      low        No     Alpha2 Alphanumeric Uppercase Encoder
   4   exploit/multi/http/struts2_namespace_ognl                   2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   5   exploit/multi/http/struts2_content_type_ognl                2017-03-07       excellent  Yes    Apache Struts Jakarta Multipart Parser OGNL Injection
   6   exploit/multi/http/tomcat_mgr_deploy                        2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   7   exploit/multi/http/tomcat_mgr_upload                        2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   8   exploit/multi/browser/itms_overflow                         2009-06-01       great      No     Apple OS X iTunes 8.1.1 ITMS Overflow
   9   exploit/osx/browser/safari_file_policy                      2011-10-12       normal     No     Apple Safari file:// Arbitrary Code Execution
   10  exploit/windows/http/ca_igateway_debug                      2005-10-06       average    Yes    CA iTechnology iGateway Debug Mode Buffer Overflow
   11  exploit/windows/rdp/cve_2019_0708_bluekeep_rce              2019-05-14       manual     Yes    CVE-2019-0708 BlueKeep RDP Remote Windows Kernel Use After Free
   12  exploit/windows/local/cve_2020_17136                        2020-03-10       normal     Yes    CVE-2020-1170 Cloud Filter Arbitrary File Creation EOP
   13  exploit/windows/http/cayin_xpost_sql_rce                    2020-06-04       excellent  Yes    Cayin xPost wayfinder_seqid SQLi to RCE
   14  auxiliary/scanner/chargen/chargen_probe                     1996-02-08       normal     No     Chargen Probe Utility
   15  payload/generic/custom                                                       normal     No     Custom Payload
   16  exploit/windows/tftp/dlink_long_filename                    2007-03-12       good       No     D-Link TFTP 1.0 Long Filename Buffer Overflow
   17  exploit/linux/http/dlink_dir850l_unauth_exec                2017-08-09       excellent  Yes    DIR-850L (Un)authenticated OS Command Exec
   18  evasion/windows/syscall_inject                                               normal     No     Direct windows syscall evasion technique
   19  exploit/linux/http/dlink_hnap_login_bof                     2016-11-07       excellent  Yes    Dlink DIR Routers Unauthenticated HNAP Login Stack Buffer Overflow
   20  exploit/windows/http/easyftp_list                           2010-02-18       great      Yes    EasyFTP Server list.html path Stack Buffer Overflow
[--------------------------------------------------------------------------------------SNIP-------------------------------------------------------------------------------------------------]
   onfusion
   55  exploit/windows/vpn/safenet_ike_11                          2009-06-01       average    No     SafeNet SoftRemote IKE Service Buffer Overflow
   56  exploit/windows/http/savant_31_overflow                     2002-09-10       great      Yes    Savant 3.1 Web Server Overflow
   57  exploit/multi/script/web_delivery                           2013-07-19       manual     No     Script Web Delivery
   58  exploit/unix/local/setuid_nmap                              2012-07-19       excellent  Yes    Setuid Nmap Exploit
   59  exploit/multi/http/simple_backdoors_exec                    2015-09-08       excellent  Yes    Simple Backdoor Shell Remote Code Execution
   60  exploit/unix/webapp/squirrelmail_pgp_plugin                 2007-07-09       manual     No     SquirrelMail PGP Plugin Command Execution (SMTP)
   61  post/windows/manage/sticky_keys                                              normal     No     Sticky Keys Persistance Module
   62  encoder/x86/opt_sub                                                          manual     No     Sub Encoder (optimised)
   63  exploit/multi/vpn/tincd_bof                                 2013-04-22       average    No     Tincd Post-Authentication Remote TCP Stack Buffer Overflow
   64  exploit/linux/http/trueonline_p660hn_v2_rce                 2016-12-26       excellent  Yes    TrueOnline / ZyXEL P660HN-T v2 Router Authenticated Command Injection
   65  exploit/windows/fileformat/vlc_mkv                          2018-05-24       great      No     VLC Media Player MKV Use After Free
   66  exploit/unix/http/vmturbo_vmtadmin_exec_noauth              2014-06-25       excellent  Yes    VMTurbo Operations Manager vmtadmin.cgi Remote Command Execution
   67  exploit/windows/fileformat/vlc_smb_uri                      2009-06-24       great      No     VideoLAN Client (VLC) Win32 smb:// URI Buffer Overflow
   68  exploit/windows/local/wmi_persistence                       2017-06-06       normal     No     WMI Event Subscription Persistence
   69  exploit/windows/vnc/winvnc_http_get                         2001-01-29       average    No     WinVNC Web Server GET Overflow
   70  exploit/windows/local/bypassuac_comhijack                   1900-01-01       excellent  Yes    Windows Escalate UAC Protection Bypass (Via COM Handler Hijack)
   71  post/windows/manage/multi_meterpreter_inject                                 normal     No     Windows Manage Inject in Memory Multiple Payloads
   72  exploit/windows/browser/yahoomessenger_server               2007-06-05       good       No     Yahoo! Messenger 8.1.0.249 ActiveX Control Buffer Overflow
   73  exploit/unix/local/at_persistence                           1997-01-01       excellent  Yes    at(1) Persistence
   74  exploit/windows/misc/mirc_privmsg_server                    2008-10-02       normal     No     mIRC PRIVMSG Handling Stack Buffer Overflow
   75  exploit/unix/http/pfsense_diag_routes_webshell              2022-02-23       excellent  Yes    pfSense Diag Routes Web Shell Upload
   76  exploit/multi/http/v0pcr3w_exec                             2013-03-23       great      Yes    v0pCr3w Web Shell Remote Code Execution
```

Ok cool. I'll try another payload

And it works 
![image](https://user-images.githubusercontent.com/113513376/213200019-2600c30f-2c70-4d5c-a7e1-c5bbc8765d1b.png)

So the web server allows upload of any file to use as a template for creating malicious binary 

So i'll upload the created payload generated now for the web server to use as template

But i need to first move the file to my current working directory
```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/ScriptKiddie]
└─$ mv /home/mark/.msf4/local/msf.apk .
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/ScriptKiddie]
└─$ 
```

My payload is ready for upload
![image](https://user-images.githubusercontent.com/113513376/213200694-39b33f84-3181-4456-a315-b4b63ecaec98.png)

But i need to catch the shell 

So i'll create a metasploit listener which will catch the reverse shell
![image](https://user-images.githubusercontent.com/113513376/213201015-737d187e-721d-4770-b524-8646bb74c889.png)

Now on uploading the file 
![image](https://user-images.githubusercontent.com/113513376/213201107-018676f2-700e-45f7-b532-3165e45b2b6e.png)

I get a call back from the listener
![image](https://user-images.githubusercontent.com/113513376/213201271-daf8aea9-180c-4768-9278-d0c6805f1ce2.png)

So i'll get a more stable reverse shell now
![image](https://user-images.githubusercontent.com/113513376/213201587-13302ec6-2ed9-433b-92c7-c74ae554ae36.png)

Now to stabilize the shell
![image](https://user-images.githubusercontent.com/113513376/213201851-115358d5-32c2-43d1-91d1-2eb872b10fe3.png)

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + z
stty raw -echo; fg
```

Privilege Escalation:

On checking /home dir we have 2 users in the box
![image](https://user-images.githubusercontent.com/113513376/213203269-ed070447-4b3a-43af-b1cf-a40c3b4ca95c.png)

The other user `pwn` has a script and we have read/ access over it

So the script is running a scan command over the ip logged in /home/kid/logs/hacker and the output is redirected to /dev/null so we won't see any output

But also it just likes greps a specific line (third line ) in the hacker log file 

Imitating the command
![image](https://user-images.githubusercontent.com/113513376/213206355-bddc11dd-fc7d-42a0-a384-5996cc519a3a.png)

I can get a command injection from here
![image](https://user-images.githubusercontent.com/113513376/213206452-71a4f3b2-8db2-4d9a-b86a-98a111e8651c.png)

So I'll edit the hacker log file to get a reverse shell by exploiting command injection

But i need to create a payload first
![image](https://user-images.githubusercontent.com/113513376/213208796-3a19c9c6-1961-44d3-8d62-0830e0e7a69d.png)

Now i'll just paste the command on the target then set a listener on my host and run the scanlog.sh file from the target

And immediately I got shell
![image](https://user-images.githubusercontent.com/113513376/213209041-f4f6a18b-9c64-41b1-a705-37592f4f5e92.png)

Now stabilizing the reverse shell 
![image](https://user-images.githubusercontent.com/113513376/213209323-1c5b02c3-1a78-406d-baeb-6d0aaa49ce14.png)

Checking sudo privilege for the user
```
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

We can run msfconsole as root without no password cool 

metasploit has the ability to run system command also 
![image](https://user-images.githubusercontent.com/113513376/213209909-9d100528-6b89-4d95-8f53-4c8c1f891c4e.png)

So i'll get a stable shell from this 
![image](https://user-images.githubusercontent.com/113513376/213210467-6d853ed1-e0f7-40af-af2b-2a849af3737f.png)

And we're done xD












