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

I created an account 
![image](https://user-images.githubusercontent.com/113513376/222960177-d3021b44-8ee6-4d36-a2fd-5b9c78c7c30d.png)

After i log in i get to the /vault
![image](https://user-images.githubusercontent.com/113513376/222960367-08e62a33-adac-49a8-8dc4-9fbb56fbbcae.png)

There are two options in it
![image](https://user-images.githubusercontent.com/113513376/222960411-2676b44b-e54f-44cc-a245-4eb35893148f.png)

To add a password vault and an export function

Clicking on export and intercepting the request shows this
![image](https://user-images.githubusercontent.com/113513376/222960451-9f4eb30c-57c5-414a-b779-33df3a4468f8.png)
![image](https://user-images.githubusercontent.com/113513376/222960464-a421d48b-a256-49ff-aae0-15ffbd6b8478.png)

Since i didn't really create a password vault it says no password found for user

So i created a password vault then intercept the request 
![image](https://user-images.githubusercontent.com/113513376/222960575-0b646e35-0b13-4c25-abbd-d0e488c4d4a6.png)
![image](https://user-images.githubusercontent.com/113513376/222960623-0a9b778e-9663-4084-8388-31b2021bb75a.png)
![image](https://user-images.githubusercontent.com/113513376/222960643-724a3c5b-0035-470c-939a-f9d35ecca685.png)
![image](https://user-images.githubusercontent.com/113513376/222960667-666014c6-0c65-468f-9565-7daa6dc30d1e.png)

It had an issue downloading the password vault file for some reason anyways noticing the url schema

```
http://superpass.htb/download?fn=pwn_export_ecc341d257.csv
```

It looks like its getting the file from the CWD 

So i'll try doing a directory transversal to read `/etc/passwd`
![image](https://user-images.githubusercontent.com/113513376/222960751-cdb5b00c-4a2c-4eb7-9e2b-43ffbb14cdb1.png)
![image](https://user-images.githubusercontent.com/113513376/222960759-826c0168-cfd6-439f-9017-c2265378fec1.png)

Cool we have directory transversal + local file read 

At this point i'll like to know where the app source code is. And the only way i can get that is by fuzzing for `/proc/FUZZ/cmdline` 

You can use ffuf to get the process then view them manually or use a bash command to curl while it fuzzed but i'll use python 

Here's my fuzz script [Fuzz](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/htb/b2b/agile/fuzz.py)

Running it takes some while but after it runs finish it creates various file*.txt 

Using a one linear bash command i'll read the content of each of them
![image](https://user-images.githubusercontent.com/113513376/222963104-6f45c1d8-ea14-4d0a-975d-9fae02e2921c.png)

Reading the output.txt file shows the process we fuzzed
![image](https://user-images.githubusercontent.com/113513376/222963170-01295977-29e3-45e6-be54-e0d326950672.png)

And its running `python3` on `app.py ( wsgi:app )`

Remember previously we generated the debug error when we tried loggin in with SQli 

Which also leaked the files

I'll download the app.py file
![image](https://user-images.githubusercontent.com/113513376/222963402-c3ae752a-b18f-4086-b5e1-d77ef90f9622.png)

Also we leaked the vault.py file from the error
![image](https://user-images.githubusercontent.com/113513376/222963444-c118eeb8-c93b-463e-a84e-d4d492aed58c.png)

Here's the file
![image](https://user-images.githubusercontent.com/113513376/222963463-b0569795-1255-4cd6-bbe2-72033f639fe9.png)

Reading the app.py shows more of like the source app file for wsgi server

But vault.py is for the /vault directory
![image](https://user-images.githubusercontent.com/113513376/222963692-2d40b12d-8759-4315-918e-a8ac53af3090.png)
![image](https://user-images.githubusercontent.com/113513376/222963707-51028b70-eb91-47ce-9448-90fea7588b0c.png)
![image](https://user-images.githubusercontent.com/113513376/222963730-6f16cd52-0cb4-41ee-b7cd-45a04e180ef2.png)
![image](https://user-images.githubusercontent.com/113513376/222963743-3814e07a-60e9-499a-9e10-d6a9d2063e80.png)



