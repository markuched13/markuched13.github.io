### Empire-Breakout Proving Grounds

### Difficulty = Easy

### IP Address = 192.168.153.238

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/EmpireBreakout]                                                                                                                                                              
└─$ nmap -sCV -A 192.168.153.238 -p80,139,445,10000,20000 -oN nmapscan                                                                                                                                             
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 20:56 WAT                                                                                                                                                    
Stats: 0:00:03 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan                                                                                                                                           
Ping Scan Timing: About 50.00% done; ETC: 20:56 (0:00:01 remaining)                                                                                                                                                
Stats: 0:00:05 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan                                                                                                                                           
Parallel DNS resolution of 1 host. Timing: About 0.00% done                                                                                                                                                        
Stats: 0:01:25 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan                                                                                                                                        
Service scan Timing: About 80.00% done; ETC: 20:58 (0:00:19 remaining)                                                                                                                                             
Nmap scan report for 192.168.153.238                                                                                                                                                                               
Host is up (0.46s latency).                                                                                                                                                                                        
                                                                                                                                                                                                                   
PORT      STATE SERVICE      VERSION                                                                                                                                                                               
80/tcp    open  http         Apache httpd 2.4.51 ((Debian))                                                                                                                                                        
|_http-server-header: Apache/2.4.51 (Debian)                                                                                                                                                                       
|_http-title: Apache2 Debian Default Page: It works                                                                                                                                                                
139/tcp   open  netbios-ssn?                                                                                                                                                                                       
445/tcp   open  netbios-ssn  Samba smbd 4.6.2                                                                                                                                                                      
10000/tcp open  http         MiniServ 1.981 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
20000/tcp open  http         MiniServ 1.830 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
|_http-server-header: MiniServ/1.830

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-25T19:59:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.55 seconds

```

Checking smb maybe we can list shares anonymously

But we can't

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/EmpireBreakout]
└─$ smbclient -L 192.168.153.238               
Password for [WORKGROUP\mark]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Samba 4.13.5-Debian)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

So what my eyes see is that there are three different web servers 

And i'll check out 10000 and 20000 

Since we know the web server running on those ports are webmin on ssl

I'll search for exploit for both `MiniServ 1.830 ` & `MiniServ 1.981 `

But after searching it seems all RCE exploits are authenticated too bad for us cause we don't have any valid cred 

And trying default cred on both webmin interface doesn't work

So now lets go back and enumerate port 80 (http)

On navigating to the web server on port 80 

It shows the default apache page
