First thing first we start with scanning the host for open ports using rustscan then use nmap to further scan those ports open

`rustscan -a 192.168.145.65`
`nmap -sCV -A -p-p21,80,135,139,445,5040,7680,9998,17001 -oN nmapscan 192.168.145.65`

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/1.png)

```
# Nmap 7.92 scan initiated Fri Jan 13 19:06:51 2023 as: nmap -sCV -A -p21,80,135,139,445,5040,7680,9998,17001 -oN nmapscan 192.168.145.65
Nmap scan report for 192.168.145.65
Host is up (0.46s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  09:31PM       <DIR>          ImapRetrieval
| 01-13-23  10:05AM       <DIR>          Logs
| 04-29-20  09:31PM       <DIR>          PopRetrieval
|_04-29-20  09:32PM       <DIR>          Spool
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
9998/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Fri, 13 Jan 2023 18:09:59 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
17001/tcp open  remoting      MS .NET Remoting services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-13T18:10:01
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 13 19:10:14 2023 -- 1 IP address (1 host up) scanned in 203.13 seconds
```

Checking out ftp since it allows anonymous connection
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/2.png)
 
 There's nothing really in other directories except the Logs directory.
 
 And checking the directories shows that there are lots of file in it
 ![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/3.png)

Anyways I got them all downloaded to check its content
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/4.png)

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/5.png)

Now i can't really start checking those log one by one so i grepped for common things like admin,password,pass,user but it doesn't really show anything of interest
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/6.png)

So this is the wrong path

From the scan we got a web server running lets check the content out
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/7.png)

So its a web mail service

I then searched for exploit on google and i got this one
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/8.png)

After editing the neccessary requirement
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/9.png)

Lets run the exploit but before that start a netcat listening on the port specified in the exploit code
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/10.png)

Back in our listener 

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Algeron/11.png)

And we're root xD

<br> <br>
[Back To Home](../../index.md)
<br>



