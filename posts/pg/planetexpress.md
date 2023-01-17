First thing first we start with scanning the host for open ports using rustscan then use nmap to further enumerate those ports open

```
# Nmap 7.92 scan initiated Fri Jan 13 16:53:16 2023 as: nmap -sCV -A -p22,80,9000 -oN nmaptcp 192.168.145.205
Nmap scan report for 192.168.145.205
Host is up (0.22s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
|_http-generator: Pico CMS
|_http-title: PlanetExpress - Coming Soon !
|_http-server-header: Apache/2.4.38 (Debian)
9000/tcp open  cslistener?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 13 16:54:02 2023 -- 1 IP address (1 host up) scanned in 45.78 seconds
```

From the scan we see that just 3 ports are open which are ssh,http,and a service nmap isn't able to fingerprint
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/1.png)

On heading to the web page doesn't really show much 

So lets hit ffuf to scan for directories
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/2.png)

When trying to access any of those directories we get 403 Forbidden 

So checking the source code of the web page shows that it uses PicoCMS
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/4.png)

So next thing i did was to search for picocms maybe i can see their main github site or maybe an exploit

And luckily we get the github site for the picocms
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/5.png)

Since the web server uses this exact web framework that means that we can get an idea of the files that's likely going to be there

And remember when we fuzzed we got few directories and one of interest which is config/ 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/6.png)

Now lets check out what the config directory should contain

On checking we see that the config directory stores a file which is config.yml in it
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/7.png)

So now lets try accessing the config.yml on the web server now 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/8.png)

And it works cool

Its time to read the config.yml file of the server and see what it does or what it has
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/9.png)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/10.png)

From this we can conclude that there's a plugin called PicoTest

Also the picocms github page shows that the plugins have an extension which is .php

Lets try seeing what this particular plugin is all about

But on navigating to the plugin directory, It shows the infomation that the phpinfo file shows
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/12.png)

Looking at it closely we see that the server uses phpfpm 7.3 and the server's api is fpm/fastcgi
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/13.png)

So i hit up google to check if there are known exploit and it turns out there is indeed one 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/14.png)

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/15.png)

So lets save this exploit code and run it

We see it just requires 4 arguments
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/16.png)

Since the exploit code requires the full path to where the vulnerable php code is I'll easily get it by viewing the PicoTest.php file
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/17.png)

Now that eveything needed is complete lets try the exploit out
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/18.png)

But it doesn't work why? maybe it disables some php execution function 

Lets confirm by reviewing the phpinfo again

And yup it does have disabled php function and `system` is among
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/18.png)

But luckily for us `passthru` isn't disabled

So lets leverage that to get command execution 

And it works quite well 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/20.png)

So lets get shell via this command execution

I saved a php reverse shell inside a file called shell.php i then hosted a python web server so that i can get the file
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/21.png)

And luckily for us the current user has write permission over the plugins/ directory 

With this we can call the shell via accessing it on the web browser
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/25.png)

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/26.png)

Now lets escalate privilege to root

On checking for SUID permission we get this 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/27.png)

A weird binary which has suid perm set on it `/usr/bin/relayd` 

Using `relayd --help` we can get the help usage for the file
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/28.png)

Hmmmm it has an option to read config from file 

Well after playing with the file for some while i figured that it set any file you attempt to read to `-r` permssion 

Lets confirm it here 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/29.png)

So now lets make /etc/shadow readable 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/30.png)

So now lets we have the hash lets brute force the password using jtr (john the ripper)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/31.png)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/PlanetExpress/32.png)

Cool we have the password hash for the root user lets login via ssh and grab the flag :)
![image](https://user-images.githubusercontent.com/113513376/212785160-5d066f30-44d6-4670-a74d-c9cf2206519e.png)


<br> <br>
[Back To Home](../../index.md)
<br>













