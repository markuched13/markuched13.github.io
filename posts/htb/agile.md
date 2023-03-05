<h3> Agile HackTheBox </h3>

#### Seasonal Machine 1

#### Difficulty = Medium

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/222959816-18341b35-f08f-4045-9244-3bbd7df0441b.png)

We see the domain name i'll it to my `/etc/hosts` file

```
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Agile]
└─$ cat /etc/hosts | grep supe
10.129.169.172  superpass.htb
```

Going over to the web server shows this
![image](https://user-images.githubusercontent.com/113513376/222960024-e08e6751-2b8c-4d55-8b5c-760ed291e89d.png)
![image](https://user-images.githubusercontent.com/113513376/222960044-88db7fe6-8ffe-4488-ad2c-44562bafbf19.png)

I tried login in with default/weak cred but it failed
![image](https://user-images.githubusercontent.com/113513376/222960096-7e240daa-86a3-421f-9209-9c20db2aefe1.png)

When i tried sqli it throws back the debug error
![image](https://user-images.githubusercontent.com/113513376/222960211-35b13542-67c9-4f7f-a613-1259cc3a9bf6.png)

W
So i created an account 
![image](https://user-images.githubusercontent.com/113513376/222960177-d3021b44-8ee6-4d36-a2fd-5b9c78c7c30d.png)
