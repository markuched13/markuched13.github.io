First thing first we start with scanning the host for open ports using rustscan then use nmap to further enumerate those ports open

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Internal/2.png)

```
# Nmap 7.92 scan initiated Fri Jan 13 17:06:34 2023 as: nmap -sCV -A -p53,135,139,445,3389,5357 -oN nmaptcp 192.168.145.40
Nmap scan report for 192.168.145.40
Host is up (0.41s latency).

PORT     STATE SERVICE            VERSION
53/tcp   open  domain             Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp  open  msrpc?
139/tcp  open  netbios-ssn?
445/tcp  open  microsoft-ds       Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2023-01-13T16:08:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=internal
| Not valid before: 2022-07-27T05:16:05
|_Not valid after:  2023-01-26T05:16:05
| rdp-ntlm-info: 
|   Target_Name: INTERNAL
|   NetBIOS_Domain_Name: INTERNAL
|   NetBIOS_Computer_Name: INTERNAL
|   DNS_Domain_Name: internal
|   DNS_Computer_Name: internal
|   Product_Version: 6.0.6001
|_  System_Time: 2023-01-13T16:07:42+00:00
5357/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
1 service unrecognized despite returning data. If you know the service/version, please submit
SF-Port139-TCP:V=7.92%I=7%D=1/13%Time=63C18194%P=x86_64-pc-linux-gnu%r(Get
SF:Request,5,"\x83\0\0\x01\x8f");
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cp

Host script results:
|_clock-skew: mean: 1h35m59s, deviation: 3h34m40s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.0.2: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:bf:22:64 (VM
| smb2-time: 
|   date: 2023-01-13T16:07:41
|_  start_date: 2022-07-28T05:16:03
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standar
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-13T08:07:41-08:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 
# Nmap done at Fri Jan 13 17:08:01 2023 -- 1 IP address (1 host up) scanned in 86.57 seconds
```
From the scan we this a windows box 
 
Lets us nmap scripting engine to identify possible vulnerability
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Internal/2.png)
 
From the result its vulnerable to CVE-2009-3103
 
I'll be using metasploit xD
 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Internal/3.png)
 
Setting the LHOST,RHOST and running the exploit we get shell as nt/authority
 ![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Internal/4.png)

  

