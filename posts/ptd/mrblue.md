### MrBlue PwntillDawn

### IP Address = 10.150.150.219

### Difficulty = Easy

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/218339581-8f8bad94-df2d-49af-9a62-37b3b05bd5ca.png)
![image](https://user-images.githubusercontent.com/113513376/218339587-344a247d-0bb8-4391-bc89-164b5f00abec.png)

From the scan we can see its a windows box. Lets begin enumerating the web server

It just shows a picture
![image](https://user-images.githubusercontent.com/113513376/218339609-bac9ebb2-7c2b-41c4-a35e-1112ed8e39aa.png)

Checking source code
![image](https://user-images.githubusercontent.com/113513376/218339615-bc127074-8fc7-49ad-bdce-9a3a54ef28fb.png)

We can see some words in the alt variable in the <img> tag and its giving reference to something

Lets check google on what MS17-010 means. And we see its an exploit which is a remote code execution cause from buffer overflow and it has its metasploit module
![image](https://user-images.githubusercontent.com/113513376/218339643-481aca29-90ed-4e8c-939e-491d2325424a.png)

On metasploit I searched for eternal blue. And we will see about 5 options so lets choose the first one then set the options
![image](https://user-images.githubusercontent.com/113513376/218339681-db1215e7-d689-4957-86e0-e49af3612bc1.png)

Running the exploit pops a shell as admin
![image](https://user-images.githubusercontent.com/113513376/218339703-6bba49e7-e33d-4d4f-bed4-5db515a4fb6c.png)

```
Flags:
Flag34: c2e9e102e55d5697ed2f9a7ea63708c1cc411b79
```

Write-ups have been authorized for this machine by the PwnTillDawn Crew! Here's the link to access it [Wizlynx](https://www.wizlynxgroup.com/) and [PwntillDawn](https://online.pwntilldawn.com/)

And we're done

<br> <br>
[Back_To_Home](../../index.md)
