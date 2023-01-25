### Assignment Proving Grounds 

### Difficulty = Easy

### IP Address = 192.168.153.224

Nmap Scan:

```
                                                                                                                                                                                     [102/102]
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Assignment]                                                                                                                                             
└─$ nmap -sCV -A 192.168.153.224 -p22,80,8000 -oN nmapscan                                                                                                                                    
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 23:54 WAT                                                                                                                               
Nmap scan report for 192.168.153.224                                                                                                                                                          
Host is up (0.22s latency).                                                                                                                                                                   
                                                                                                                                                                                              
PORT     STATE SERVICE  VERSION                                                                                                                                                               
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)                                                                                                          
| ssh-hostkey:                                                                                                                                                                                
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)                                                                                                                                
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)                                                                                                                               
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)                                                                                                                             
80/tcp   open  http                                                                                                                                                                           
| fingerprint-strings:                                                                                                                                                                        
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMB
ProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:                                                           
|     HTTP/1.1 400 Bad Request                                                                                                                                                                
|   FourOhFourRequest, GetRequest, HTTPOptions:                                                                                                                                               
|     HTTP/1.0 403 Forbidden                                                                                                                                                                  
|     Content-Type: text/html; charset=UTF-8                                                                                                                                                  
|_    Content-Length: 0                                                                                                                                                                       
|_http-title: notes.pg                                                                                                                                                                        
8000/tcp open  http-alt                                                                                                                                                                       
| fingerprint-strings:                                                                                                                                                                        
|   FourOhFourRequest:                                                                                                                                                                        
|     HTTP/1.0 404 Not Found                                                                                                                                                                  
|     Content-Type: text/html; charset=UTF-8                                                                                                                                                  
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647                                                                                                                                      
|     Set-Cookie: i_like_gogs=0617c5f1cb796894; Path=/; HttpOnly                                                                                                                              
|     Set-Cookie: _csrf=_RcOSVCfcAL-nOqvt_r6eB9MzX06MTY3NDY4NzI3NDI1MzAwMDkwOA; Path=/; Domain=assignment.pg; Expires=Thu, 26 Jan 2023 22:54:34 GMT; HttpOnly                                 
|     X-Content-Type-Options: nosniff                                                                                                                                                         
|     X-Frame-Options: DENY                                                                                                                                                                   
|     Date: Wed, 25 Jan 2023 22:54:34 GMT                                                                                                                                                     
|     <!DOCTYPE html>                                                                                                                                                                         
|     <html>                                                                                                                                                                                  
|     <head data-suburl="">                                                                                                                                                                   
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />                                                                                                                   
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>                                                                                                                                  
|     <meta name="author" content="Gogs" />                                                                                                                                                   
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />                                                                                                        
|     <meta name="keywords" content="go, git, self-hosted, gogs">                                                                                                                             
|     <meta name="referrer" content="no-referrer" />                                                                                                                                          
|     <meta name="_csrf" content="_RcOSVCfcAL-nOqvt_r6eB9MzX06MTY3NDY4Nz                                                                                                                      
|   GenericLines:           
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=1b0f362ac02e9f17; Path=/; HttpOnly
|     Set-Cookie: _csrf=X7nT8HRfZjdhOhvh9LMzyGx_hkY6MTY3NDY4NzI2ODU5Njg0NzczMw; Path=/; Domain=assignment.pg; Expires=Thu, 26 Jan 2023 22:54:28 GMT; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: DENY
|     Date: Wed, 25 Jan 2023 22:54:28 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|_    <meta name="_csrf" content="X7nT8HRfZjdhOhvh9LMzyGx_hkY6MTY3NDY4NzI2ODU5N
|_http-title: Gogs
|_http-open-proxy: Proxy might be redirecting requests
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

Checking the web server on port 80 

Shows that its a note taking site

