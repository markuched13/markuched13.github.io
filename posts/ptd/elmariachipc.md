### ElMariachi-PC PwntillDawn

### IP Address = 10.150.150.69

### Difficulty = Easy

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/218337866-3a3e77e2-5d4a-4ed8-9b33-0aa344596edf.png)

From the scan we can see its a windows box. So lets enumerate the smb server
![image](https://user-images.githubusercontent.com/113513376/218337876-14d5865a-8950-4dd4-b72e-4588df06b6c9.png)

It shows that we can't list shares anonymously. On looking at the ports we can see a weird port on 5040 and nmap isn't able to identify the service running on it

I tried connecting to it using netcat but I didn't get any response
![image](https://user-images.githubusercontent.com/113513376/218337908-596d452c-c34e-4358-87ab-35990ede4ecd.png)

Lets get back to the smb port and try further enumeration. Using the metasploit module, I attempted to brute force but wasn't successfull
![image](https://user-images.githubusercontent.com/113513376/218337942-61f03f22-9c41-4f21-8daf-598ff22b467b.png)

At this point I rescanned the host again and got another port which was running thinvnc on port 60000
![image](https://user-images.githubusercontent.com/113513376/218337953-116badc7-0eab-49a3-9e4b-3fcab9959c67.png)

I checked out metasploit to see if there's any thing on it. Cool there is 
![image](https://user-images.githubusercontent.com/113513376/218337964-ceabc259-538e-4924-b4ba-e5ebe3069f3e.png)

I'll use the exploit
![image](https://user-images.githubusercontent.com/113513376/218337998-f0197f71-7630-4312-a0b6-bb7f770adf76.png)

And it gave us a credential `desperado:TooComplicatedToGuessMeAhahahahahahahh`. I'll login via rdp using newly found credential
![image](https://user-images.githubusercontent.com/113513376/218338011-e881c022-6d1b-401c-85f3-868d53a56507.png)
![image](https://user-images.githubusercontent.com/113513376/218338013-e42c0972-830e-48fc-b701-411c5f7bfa7c.png)
![image](https://user-images.githubusercontent.com/113513376/218338020-8a796c87-1d4c-40d9-b6cc-efda7f13c369.png)

```
Flags:
Flag67: 2971f3459fe55db1237aad5e0f0a259a41633962
```

And we're done

Write-ups have been authorized for this machine by the PwnTillDawn Crew! Here's the link to access it [Wizlynx](https://www.wizlynxgroup.com/) and [PwntillDawn](https://online.pwntilldawn.com/)

<br> <br>
[Back To Home](../../index.md)
