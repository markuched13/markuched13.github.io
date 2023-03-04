<h3> Surf Proving Grounds Practice </h3>

### Difficulty = Intermediate

### IP Address = 192.168.126.171

Nmap Scan:

```
─$ cat nmapscan                                 
# Nmap 7.92 scan initiated Sat Mar  4 00:55:39 2023 as: nmap -sCV -A -p22,80 -oN nmapscan 192.168.126.171
Nmap scan report for 192.168.126.171
Host is up (0.43s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Surfing blog
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  4 00:55:51 2023 -- 1 IP address (1 host up) scanned in 12.43 seconds
```

Checking the web server on port shows this
![image](https://user-images.githubusercontent.com/113513376/222858069-45e0154a-d397-4557-8cae-ae363a1ecd46.png)

Nothing really much there except 2 posts talking about surfing

I ran gobuster on it and found this 
![image](https://user-images.githubusercontent.com/113513376/222858382-93338bcb-363b-4111-8cd0-860a7376e1bf.png)

Going on to /administration shows a login page
![image](https://user-images.githubusercontent.com/113513376/222858175-0b148573-0a6c-4914-80bf-c0223930ba98.png)

Trying default/weak cred doesn't work

So i noticed the request in burp and saw a cookie which caught my attention
![image](https://user-images.githubusercontent.com/113513376/222858228-a991a10f-e8ee-4cf4-9e82-021a59826ab9.png)

```
Cookie: auth_status=eydzdWNjZXNzJzonZmFsc2UnfQ==; PHPSESSID=ie6k33s7t2ahuop2kuqpcm2hc5
```

Decoding the cookie with base64 decode shows its value

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Surf]
└─$ echo eydzdWNjZXNzJzonZmFsc2UnfQ== | base64 -d                   
{'success':'false'}     
```

I'll generate a new cookie and replace it with the request cookie

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Surf]
└─$ echo -n "{'success':'true'}" | base64                      
eydzdWNjZXNzJzondHJ1ZSd9
```

Now i'll replace it 
![image](https://user-images.githubusercontent.com/113513376/222858627-3610e4b5-733b-44f1-8384-a868f8c44921.png)

And i get logged in
![image](https://user-images.githubusercontent.com/113513376/222858670-d37baf7b-bfe1-49ab-9725-e9aef0949e56.png)

After poking around the web page i got this that we had just few access over some functions

We can create a user and exploit the customers list in form of a csv file
![image](https://user-images.githubusercontent.com/113513376/222859229-c8083690-3f55-4603-9b8a-498371d3dc65.png)

Trying to access the shell console gives an error
![image](https://user-images.githubusercontent.com/113513376/222859558-e5c5d862-3383-48e9-b1d9-d71a50ecb2d4.png)

There's another function called check server status clicking it just shows that the server is running
![image](https://user-images.githubusercontent.com/113513376/222859633-b29c8533-afdd-4a13-a488-1f742dd1520a.png)

Hmmmm lets intercept the request in burp and check what happens when we click the check button
![image](https://user-images.githubusercontent.com/113513376/222859681-c2ac604c-2b2f-480e-ae0d-205823eb0311.png)

Cool we see that its accessing the internal service

```
url=http://127.0.0.1:8080
```

Therefore this is an SSRF vulnerability



