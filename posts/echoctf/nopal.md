### Nopal EchoCTF

### Difficulty = Intermediate

### IP Address =  10.0.30.124

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/220216925-7f47fccc-9b2b-4eb9-ac9d-8a65b5ab0448.png)

Only 1 tcp port open 

On checking the web server shows an instance of Cacti
![image](https://user-images.githubusercontent.com/113513376/220217000-6a685392-2004-47fd-9287-70fb6898e233.png)

After i searched for default cred i couldn't find any

Looking at the web page shows it version `Cacti Version 1.2.8`

Searching for exploit leads here [Exploit](https://github.com/m4udSec/Cacti-CVE-2020-8813)

Running the exploit gives shell
![image](https://user-images.githubusercontent.com/113513376/220217230-6cd11e94-84fe-4284-8355-381f20681853.png)

Stabilizing the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
```

Looking for internal service shows that snmp port is open
![image](https://user-images.githubusercontent.com/113513376/220217379-0de74d18-5b25-4013-835b-f38e71eafeac.png)

Reading the config file shows that the community key is `public` 
![image](https://user-images.githubusercontent.com/113513376/220217539-4013fde8-72fc-4dfd-84e6-5baaf48c3205.png)

Also it runs an extend command on `/tmp/snmpd-tests.sh`

So what extend does is that whenever a walk is done on snmp it will run the file specified as a bash file 

With that we can get code execution 

Here's the resource that helped me out [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce)

I'll create the file `snmpd-tests.sh` in the `/tmp` directory and add the content of a bash reverse shell
![image](https://user-images.githubusercontent.com/113513376/220217801-3c8efba5-693f-4ddc-9fe9-30b9f4788031.png)

With that i'll set a listener on port 1337 and run the snmpwalk command

```
cd /tmp
snmpwalk localhost -c public -v1 . 
```

Running it pops our shell 🤓
![image](https://user-images.githubusercontent.com/113513376/220217966-979b432f-2bed-45ae-b426-26297a81617b.png)

And we're done xD

<br> <br>
[Back To Home](../../index.md)
