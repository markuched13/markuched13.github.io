### PwnDrive Academy PwntillDawn

### IP Address = 10.150.150.11

### Difficulty = Easy

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/218336919-f5afa599-3d66-44d5-869b-b62834a4fc32.png)
![image](https://user-images.githubusercontent.com/113513376/218336930-d7388bde-7fa8-4c05-8d59-e9c5cf6eedae.png)

From the scan we can tell its a windows box. So there are quite some attack vectors on this box but I'll be dealing with port 80

On heading to the web page we can see its some sort of web service that allows user save things in the cloud
![image](https://user-images.githubusercontent.com/113513376/218336961-b9d60d61-0e87-4f0f-b61b-74df31ab734f.png)


And we can see a sign in function lets try signing in

So one thing we should try when dealing with login page is default credential or sql injection

As I've done it before both works and its obvious sqli worked cause we had a mysql service running when we did port scan i guess 🤔
![image](https://user-images.githubusercontent.com/113513376/218337032-418e2b23-ba25-490e-98a2-cb38c474d563.png)

But in this case i used default credential which is admin:admin

We are logged in, on looking at the function we can see it allows adding of file 

But before we proceed lets check the web server technology because if we want to abuse it we need to upload a file that the web server will be able to understand which can lead to remote code execution
![image](https://user-images.githubusercontent.com/113513376/218337083-80940083-15ab-4c41-8807-68a04cadce4d.png)

So I used wappalzer and we can see the web server programming language is php
![image](https://user-images.githubusercontent.com/113513376/218337099-68de16f2-50fd-41c7-85f6-6919538af2a6.png)

So now i will try uploading a php code exection payload
![image](https://user-images.githubusercontent.com/113513376/218337110-97cadbc4-81ba-4c22-81a3-15d10f732331.png)

Now i'll upload it to the web server. And as we can see the file uploaded successfully
![image](https://user-images.githubusercontent.com/113513376/218337116-b58a9264-042e-4b28-a5d7-ef2a1992b331.png)

Fuzz for where the file uploaded to. I used gobuster and from the result we get a valid directory
![image](https://user-images.githubusercontent.com/113513376/218337151-7551cd6a-9184-46f0-a746-fc1e39c22358.png)

Now lets check it out. And yeah the file we uploaded is in there. Now lets execute command on the target using that payload
![image](https://user-images.githubusercontent.com/113513376/218337167-f4efbc01-1cf6-4250-8428-ca32b8715d3b.png)

As we can see we are admin (highest privileged user on the windows host) on the server
![image](https://user-images.githubusercontent.com/113513376/218337190-8a77cbff-638a-40fb-a09d-337a44a786dc.png)

I can get a reverse shell with this code execution

I'll be using revshell.com payload to pick my reverse shell. And I'll also have to urlencode the payload
![image](https://user-images.githubusercontent.com/113513376/218337256-732dc298-1e3e-493a-926a-7cb464efb4d0.png)
![image](https://user-images.githubusercontent.com/113513376/218337249-07fad8f9-0688-4fdd-9562-d78d1d5e26e4.png)

Now on sending the payload to the web server we get our shell
![image](https://user-images.githubusercontent.com/113513376/218337279-62ebc161-f8e5-44e6-99a9-fd5c985cf275.png)
![image](https://user-images.githubusercontent.com/113513376/218337287-d58965f2-575b-429c-8db9-5fd6bba70ec7.png)

And we're done 

<br> <br> 
[Back To Home](../../index.md)

