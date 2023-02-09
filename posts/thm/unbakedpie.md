### UnbackedPie TryHackMe

### Difficulty = Medium

Nmap Scan:

```
# Nmap 7.92 scan initiated Sat Jan  7 04:17:47 2023 as: nmap -sCV -p 5003 -oN nmapscan -Pn 10.10.186.73
Nmap scan report for 10.10.186.73
Host is up (0.17s latency).

PORT     STATE SERVICE    VERSION
5003/tcp open  filemaker?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 07 Jan 2023 03:17:54 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=54Ujr9NU5L86w9hShEChqIAlsZCoJBLfgBTxz7gYM1G7mS92Q4OX65hCB31xitni; expires=Sat, 06 Jan 2024 03:17:54 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|     <link href="/static/vendor/fontawesome-free/css/all.min.cs
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 07 Jan 2023 03:17:55 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=FMOXTiI41MdRPJ8TtubJzr01YLpaXXzJCzRYMdwruz4DpMKympew4W9Dk0QEqMq1; expires=Sat, 06 Jan 2024 03:17:55 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|_    <link href="/static/vendor/fontawesome-free/css/all.min.cs
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5003-TCP:V=7.92%I=7%D=1/7%Time=63B8E462%P=x86_64-pc-linux-gnu%r(Get
SF:Request,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2007\x20Jan\x202
SF:023\x2003:17:54\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8\.6
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:\x2
SF:0DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Type-O
SF:ptions:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie:\x2
SF:0\x20csrftoken=54Ujr9NU5L86w9hShEChqIAlsZCoJBLfgBTxz7gYM1G7mS92Q4OX65hC
SF:B31xitni;\x20expires=Sat,\x2006\x20Jan\x202024\x2003:17:54\x20GMT;\x20M
SF:ax-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20html>
SF:\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf-8\"
SF:>\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\
SF:x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\"des
SF:cription\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20conten
SF:t=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x20<!-
SF:-\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/static/v
SF:endor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\n\x2
SF:0\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x20\x2
SF:0<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs")%r(H
SF:TTPOptions,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2007\x20Jan\x
SF:202023\x2003:17:55\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8
SF:\.6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:
SF:\x20DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Typ
SF:e-Options:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie:
SF:\x20\x20csrftoken=FMOXTiI41MdRPJ8TtubJzr01YLpaXXzJCzRYMdwruz4DpMKympew4
SF:W9Dk0QEqMq1;\x20expires=Sat,\x2006\x20Jan\x202024\x2003:17:55\x20GMT;\x
SF:20Max-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20ht
SF:ml>\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf-
SF:8\">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-widt
SF:h,\x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\"
SF:description\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20con
SF:tent=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x20
SF:<!--\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/stati
SF:c/vendor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\n
SF:\x20\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x20
SF:\x20<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan  7 04:19:22 2023 -- 1 IP address (1 host up) scanned in 95.23 seconds
```
