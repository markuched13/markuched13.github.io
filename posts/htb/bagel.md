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
