### Django PwntillDawn

### IP Address = 10.150.150.212

### Difficulty = Easy

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/218338271-707b36a3-d176-48d2-a474-a7f171f73162.png)
![image](https://user-images.githubusercontent.com/113513376/218338279-282e9059-83b2-4092-9b77-afca783dabb9.png)

From the scan we can see its a windows box which has various services running on it

Lets start our enumeration on port 21 which is ftp
![image](https://user-images.githubusercontent.com/113513376/218338292-3debd382-c41f-44df-9179-9c5c4a0c3a37.png)

Now lets view the content of all the files we got from the ftp server

The first file which was xampp log had so many content in it 599 lines
![image](https://user-images.githubusercontent.com/113513376/218338314-b85fc756-868e-4472-92a2-06f49b44a9b9.png)

Instead of me reading the file line by line i decided to use grep on common things like password, users, etc.
![image](https://user-images.githubusercontent.com/113513376/218338327-a4dc4fba-c744-43e1-8ae3-abf063e172c8.png)

It shows that the xampp service is writting password in the c:\xampp directory

Now lets view the content of zen.txt, but it seems to be some sort of poem
![image](https://user-images.githubusercontent.com/113513376/218338375-15d02440-6208-428b-8d04-4ce8d9077918.png)

Also I decided to check if the host is vulnerable to eternal blue since its a windows 7 host. But it wasn't vulnerable
![image](https://user-images.githubusercontent.com/113513376/218338383-817b1101-ca01-46d6-851a-b1bee6b0809d.png)

But if we remember the log file we got from ftp, it disclosed the directory where password are stored. Lets check if we can get that from the ftp server
![image](https://user-images.githubusercontent.com/113513376/218338420-70b70400-d3b2-4818-8ec9-817febb871b2.png)

It removed the `\` lets add one more `\`
![image](https://user-images.githubusercontent.com/113513376/218338439-77ff2c7d-66a1-47d7-b99f-7dbe962935ff.png)

And it worked lets now view the content on our machine
![image](https://user-images.githubusercontent.com/113513376/218338450-7fa23cc9-53ca-4da3-9738-c59e9fe40040.png)

From the result it shows the passwords for various service

Lets check out the mysql so its either we use the standart port on 3306 and login via it or we use phpmyadmin

But in this case I'll be using mysql. So when I tried connecting to mysql I get an error that user is not allowed to connect to the mysql server
![image](https://user-images.githubusercontent.com/113513376/218338476-c4555fa7-dd64-43f5-8d82-f696204356c8.png)

Instead lets go with the other alternative which is phpmyadmin 
![image](https://user-images.githubusercontent.com/113513376/218338492-efc9463f-bbcd-45ec-8a27-0b7a593d4e89.png)

To get shell via exploiting phpmyadmin is possible so I used this article to help me get shell with it https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/

So what basically happens is just the same as exploiting using the cli way but rather this is in gui

Firsly create a new database, then put the malicious php file inside the webroot directory then access the shell on the web page
![image](https://user-images.githubusercontent.com/113513376/218338526-13b9b5d0-afb2-429f-9ef7-56f5ff04285d.png)
![image](https://user-images.githubusercontent.com/113513376/218338539-4ce909ad-cf12-4839-8057-1c350e422863.png)

Lets get our reverse shell. I used powershell reverse shell from revshells.com
![image](https://user-images.githubusercontent.com/113513376/218338564-8b1a7dcd-0dc4-43d9-8b28-ff77a1d21e1f.png)

So since chuck.norris also has admin right on the machine there's no need to pivot unless we want to do post exploitation :(
![image](https://user-images.githubusercontent.com/113513376/218338587-ac3d6fa2-764d-49fc-bdac-1b8a4c3e6028.png)

Write-ups have been authorized for this machine by the PwnTillDawn Crew! Here's the link to access it [Wizlynx](https://www.wizlynxgroup.com/) and [PwntillDawn]( https://online.pwntilldawn.com/)

```
Flags:
Flag11: 7a763d39f68ece1edd1037074ff8d129451af0b1
Flag18: ad1357d394eba91febe5a6d33dd3ec6dd0abc056
Flag19: a393b6fb540379e942b0010afa3058985fb8cec3
Flag20: a9435c140b6667cf2f24fcf6a9a1ea6b8574c3e7
```

And we're done 

<br> <br>
[Back To Home](../../index.md)

