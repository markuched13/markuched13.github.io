### HollyWood PwntillDawn

### IP Address = 10.150.150.219

### Difficulty = Easy

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/218339136-4a7ab234-814f-4598-9a18-c27460302adb.png)
![image](https://user-images.githubusercontent.com/113513376/218339150-979f32f8-5fa3-46e1-8fcb-609a8f7acb13.png)
![image](https://user-images.githubusercontent.com/113513376/218339157-330d5209-7d36-4ff1-82b1-fa948d9e9911.png)

From the scan we can see its a windows machine with lot of ports. So lets get enumerating

I'll start with port 21 which is ftp. But it doesn't allow anonymous authentication
![image](https://user-images.githubusercontent.com/113513376/218339192-107841e1-6869-45f3-8260-6cae1663af8a.png)

So lets move on. Going on to smb shows we can't list shares anonymously either
![image](https://user-images.githubusercontent.com/113513376/218339214-fca83a97-c5c9-49ba-8139-199eb18bf01a.png)

But what got me thinking is those web servers running on various ports

I started to check out each web server starting from port 2224. But It got nothing interesting

I noticed some of the web servers, that nmap finger printed its service name

I started with the apache tomcat instance hosted on port 8080

I did also try brute forcing the manager login using a metasploit module but I wasn't successful. I also tried ghostcat exploit which will read the WEB-inf config file for the apache tomcat but it didn't leak its credential

So I moved on to another web server

On checking the web server on port 8161 nmap fingerprinted it that the service name is Jetty 8.1.16.v20140903. On navigating to the web server we get a default page
![image](https://user-images.githubusercontent.com/113513376/218339276-f8902665-2625-4a79-b9a9-e64f9406f0a2.png)

But noticing the http title and the default page it shows ActiveMQ

I searched for it in metasploit and it seems there are possible exploits for it
![image](https://user-images.githubusercontent.com/113513376/218339296-900ab0b5-0914-46f4-a1e7-6968c8a00c49.png)

And I'll try exploit 1
![image](https://user-images.githubusercontent.com/113513376/218339307-3b9b07e6-54f4-4656-bf97-c9462147153f.png)

Running it we get shell
![image](https://user-images.githubusercontent.com/113513376/218339322-c34ebbb2-b7c8-45a5-a340-3230fc8839be.png)

And our current user has admin rights. So we can do things like hash dumping and other cool stuffs
![image](https://user-images.githubusercontent.com/113513376/218339343-060d02f0-0a04-4d47-b885-fc968b2e15a3.png)

```
Flags:
Flag9: b017cd11a8def6b4bae78b0a96a698deda09f033
Flag30: eb1b768800000e1d2fe1c3100005d2dc8dd10000
Flag33: 1480d39af2cd8b0f0bb8c45d331caf7330faa910
```

Write-ups have been authorized for this machine by the PwnTillDawn Crew! Here's the link to access it [Wizlynx](https://www.wizlynxgroup.com/) and [PwntillDawn](https://online.pwntilldawn.com/) 

And we're done

<br> <br> 
[Back To Home](../../index.md)
