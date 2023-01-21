### Roquefort Proving Ground Practice

### Difficulty = Hard

### IP Address = 192.168.88.67

Nmap Scan: 

```                                                                                                                                                                                                               
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Exghost]
└─$ nmap -sCV -A 192.18.8867 -p21,22,2222,3000 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 22:13 WAT
Nmap scan report for 192.18.8867 (192.18.34.163)
Host is up.

PORT     STATE    SERVICE      VERSION
21/tcp   filtered ftp
22/tcp   filtered ssh
2222/tcp filtered EtherNetIP-1
3000/tcp filtered ppp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.48 seconds
```

Wow nothing of interest cause the ports are filtered

Attempting to connect to ftp shows the ftp version

```
┌──(markhaxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ ftp 192.168.88.67
Connected to 192.168.88.67.
220 ProFTPD 1.3.5b Server (Debian) [::ffff:192.168.88.67]
Name (192.168.88.67:mark): anonymous
331 Password required for anonymous
Password: 
530 Login incorrect.
ftp: Login failed
ftp> ^D
221 Goodbye.
```

Searching for known exploits on ProFTPD 1.3.5b

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ searchsploit proftpd 1.3.5 
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                   |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                                        | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                                              | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                                                          | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                                                                                        | linux/remote/36742.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                                                   
```

Well non of it actually turns out to be working for that version of ftp in it

Lets check out other ports 22, 2222 & 3000

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ nc 192.168.88.67 22  
SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
^C
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ nc 192.168.88.67 2222
SSH-2.0-dropbear_2016.74
|8?4n>Aqicurve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,kexguess2@matt.ucc.asn.au#ecdsa-sha2-nistp521,ssh-rsa,ssh-dssgaes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,twofish256-cbc,twofish-cbc,twofish128-cbc,3des-ctr,3des-cbcgaes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,twofish256-cbc,twofish-cbc,twofish128-cbc,3des-ctr,3des-cbc;hmac-sha1-96,hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-md5;hmac-sha1-96,hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-md5zlib@openssh.com,nonezlib@openssh.com,noneo^C
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ nc 192.168.88.67 3000
GET / 
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close

400 Bad Request                                                                                                                                                                                                                   
```

So only port 3000 thats a web server the remaining 22 & 2222 are ssh server 

Lets hit the web server then :)

And its a gitea instance 
![image](https://user-images.githubusercontent.com/113513376/213887762-2a62f2ac-0602-431d-a9a7-c578690a4ed1.png)

Below the page shows the gitea version which is 1.7.5 
![image](https://user-images.githubusercontent.com/113513376/213887836-839434f2-7531-4a44-8396-abd184ece9e1.png)

Hitting google is there's known exploit returns this but its an authenticated rce https://www.exploit-db.com/exploits/49383
![image](https://user-images.githubusercontent.com/113513376/213887850-36539630-861f-4b08-bb91-a1d59766b08d.png)

At this point we don't have credential 

So lets check out other things

I tried loggin in with username admin with different weak credentials but it failed 
![image](https://user-images.githubusercontent.com/113513376/213887879-3922fd81-bbaa-4479-99b1-c5209dc01c20.png)

So rather lets create an account and see what we can get from exploring repository there
![image](https://user-images.githubusercontent.com/113513376/213887907-b49461db-ad6c-40ff-96cf-2895a781ee0a.png)

```
Username: hacker
Email: hacker@localhost.com
Password: hacker
Re-Type Password: hacker
```

It worked
![image](https://user-images.githubusercontent.com/113513376/213887963-c87992a7-ae17-49c2-b352-eac2758b529a.png)

So i just taught of something right now 

Instead of attempting to explore possible repository 

We can instead use the credential on the exploit 🙂

Now i just need to edit the required variables
![image](https://user-images.githubusercontent.com/113513376/213888032-ea6e6187-fd38-4276-ab0a-92b95539b337.png)


So we need to set a python web server on port 8080 which has a file called shell that will grant us a reverse shell 

But instead i'll 



