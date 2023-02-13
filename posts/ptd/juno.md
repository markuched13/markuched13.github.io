### Juno PwntillDawn

### IP Address = 	10.150.150.224

### Difficulty = Medium

Nmap Scan:

```
└─$ nmap -sCV -A 10.150.150.224 -p80 -oN nmapscan 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-13 00:12 WAT
Nmap scan report for 10.150.150.224
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.44 seconds
```

Checking the web server shows the default apache2 file
![image](https://user-images.githubusercontent.com/113513376/218343074-61937f91-ef48-4ad3-9636-6e151a9d68b3.png)

I'll run gobuster to fuzz for directories and files

```
└─$ gobuster dir -u http://10.150.150.224/ -w /usr/share/wordlists/dirb/common.txt -x php
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.150.150.224/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/13 00:14:23 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/login.php            (Status: 200) [Size: 1213]
/registered.php       (Status: 403) [Size: 9]
/server-status        (Status: 403) [Size: 279]
Progress: 9208 / 9230 (99.76%)
===============================================================
2023/02/13 00:17:23 Finished
===============================================================
```

Cool i'll check out login.php
![image](https://user-images.githubusercontent.com/113513376/218343762-40ceacff-474c-4d26-863e-a49032fb7dd2.png)

It shows a login page

Checking the other file shows that we can't access it
![image](https://user-images.githubusercontent.com/113513376/218343806-8184b3f2-0f9e-44ee-a4d0-63e1b7190a56.png)

This means that we're working with the login page

I would have attempt brute force if the length of the pin is known but it isn't
![image](https://user-images.githubusercontent.com/113513376/218343859-d3bdd69e-6755-4168-8e0c-df798dba0251.png)

Below the web page shows some app download clicking it downloads an apk file
![image](https://user-images.githubusercontent.com/113513376/218343887-3ba2b523-145b-470e-b9d2-cf6deb2b45cf.png)

I'll decompile it using jd-gui

But before i do that i need to convert it to a zip file then unzip it 

After that i'll convert the classes.dex to a jar file

```
└─$ ls
JunoClient.apk
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/B2B/Pwntilldawn/Juno/apkrev]
└─$ file JunoClient.apk 
JunoClient.apk: Zip archive data, at least v2.0 to extract, compression method=deflate
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/B2B/Pwntilldawn/Juno/apkrev]
└─$ mv JunoClient.apk JunoClient.zip 
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/B2B/Pwntilldawn/Juno/apkrev]
└─$ unzip JunoClient.zip     
Archive:  JunoClient.zip
  inflating: AndroidManifest.xml     
  inflating: META-INF/CERT.RSA       
  inflating: META-INF/CERT.SF        
  inflating: META-INF/MANIFEST.MF    
  inflating: classes.dex             
  inflating: res/anim/abc_fade_in.xml  
  inflating: res/anim/abc_fade_out.xml  
  inflating: res/anim/abc_grow_fade_in_from_bottom.xml  
  inflating: res/anim/abc_popup_enter.xml  
  inflating: res/anim/abc_popup_exit.xml  
  inflating: res/anim/abc_shrink_fade_out_from_bottom.xml  
  inflating: res/anim/abc_slide_in_bottom.xml  
  inflating: res/anim/abc_slide_in_top.xml  
  inflating: res/anim/abc_slide_out_bottom.xml  
  inflating: res/anim/abc_slide_out_top.xml  
  inflating: res/anim/tooltip_enter.xml  
  inflating: res/anim/tooltip_exit.xml  
 extracting: res/drawable-xhdpi-v4/abc_scrubber_track_mtrl_alpha.9.png  
 extracting: res/drawable-xhdpi-v4/abc_spinner_mtrl_am_alpha.9.png  
 extracting: res/drawable-xxxhdpi-v4/abc_ic_star_black_16dp.png  
 extracting: res/drawable-xxxhdpi-v4/abc_ic_star_black_36dp.png  
 extracting: res/drawable-xxxhdpi-v4/abc_ic_star_black_48dp.png  
 [[---------------SNIP------------------]]
 extracting: res/drawable-xxxhdpi-v4/abc_ic_star_half_black_16dp.png  
 extracting: res/drawable-xxxhdpi-v4/abc_ic_star_half_black_36dp.png  
 extracting: res/drawable-xxxhdpi-v4/abc_ic_star_half_black_48dp.png  
 extracting: res/drawable-xxxhdpi-v4/abc_scrubber_control_to_pressed_mtrl_000.png  
 extracting: res/drawable-xxxhdpi-v4/abc_scrubber_control_to_pressed_mtrl_005.png  
 extracting: res/drawable-xxxhdpi-v4/abc_spinner_mtrl_am_alpha.9.png  
 extracting: res/mipmap-xhdpi-v4/ic_launcher.png  
 extracting: res/mipmap-xhdpi-v4/ic_launcher_round.png  
 extracting: res/mipmap-xxhdpi-v4/ic_launcher.png  
 extracting: res/mipmap-xxhdpi-v4/ic_launcher_round.png  
 extracting: res/mipmap-xxxhdpi-v4/ic_launcher.png  
 extracting: res/mipmap-xxxhdpi-v4/ic_launcher_round.png  
 extracting: resources.arsc          
```

Now i'll convert the classes.dex file to a jar file using [dex2jar](https://github.com/pxb1988/dex2jar/releases/tag/v2.1)

```
┌──(mark㉿haxor)-[~/…/B2B/Pwntilldawn/Juno/apkrev]
└─$ bash /opt/dex-tools-2.1/d2j-dex2jar.sh classes.dex 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
dex2jar classes.dex -> ./classes-dex2jar.jar
                                                                                                                                                                                                                   
┌──(mark㉿haxor)-[~/…/B2B/Pwntilldawn/Juno/apkrev]
└─$ ls -l classes-dex2jar.jar 
-rw-r--r-- 1 mark mark 2098668 Feb 13 00:40 classes-dex2jar.jar
```

Now i'll decompile using jd-gui

Looking at the EncoderDecoder class shows it encrypt and decrypt function
![image](https://user-images.githubusercontent.com/113513376/218345008-ba658784-c8a0-43ee-a515-ceee08dcd634.png)

```
package com.wizlynxgroup.mobile.junoclientsample;

import android.util.Base64;

public class EncoderDecoder {
  private byte[] andWithKey(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte = new byte[paramArrayOfbyte1.length];
    for (byte b = 0; b < paramArrayOfbyte1.length; b++)
      arrayOfByte[b] = (byte)(byte)(paramArrayOfbyte1[b] & paramArrayOfbyte2[b % paramArrayOfbyte2.length]); 
    return arrayOfByte;
  }
  
  private byte[] orWithKey(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte = new byte[paramArrayOfbyte1.length];
    for (byte b = 0; b < paramArrayOfbyte1.length; b++)
      arrayOfByte[b] = (byte)(byte)(paramArrayOfbyte1[b] | paramArrayOfbyte2[b % paramArrayOfbyte2.length]); 
    return arrayOfByte;
  }
  
  public String customEncode(String paramString) {
    byte[] arrayOfByte = paramString.getBytes();
    for (byte b = 0; b < ''; b++)
      arrayOfByte = Base64.encodeToString(arrayOfByte, 0).getBytes(); 
    return new String(arrayOfByte);
  }
  
  public String junoHomeMadeEncode(String paramString) {
    char[] arrayOfChar = new char[paramString.length()];
    for (byte b = 0; b < arrayOfChar.length; b++)
      arrayOfChar[b] = (char)(char)(paramString.charAt(b) + 4); 
    return new String(arrayOfChar);
  }
  
  public String myDecode(String paramString1, String paramString2) {
    return paramString1.equals(paramString1.substring(0)) ? new String(andWithKey(Base64.decode(paramString1, 0), paramString2.getBytes())) : new String(orWithKey(Base64.decode(paramString1, 0), paramString2.getBytes()));
  }
}
```

I have no idea in java but i think the encrypt function justs base64 encode each character of the input 🤔

Anyways i can seem to just find any some of string thats not encoded and looking through all this files is a pain 

So instead i'll dynamically analyze using [mobsf](https://github.com/MobSF/Mobile-Security-Framework-MobSF.git)

After starting an instance of mobsf and uploading the apk file, mobsf will gather all readable string gotten from each classes file in the apk

It also made the encode/decode func look readable
![image](https://user-images.githubusercontent.com/113513376/218345878-c2be9eaf-8d70-454f-bb6a-f1c6f776f1a1.png)

Scrolling down shows me a word which has a key
![image](https://user-images.githubusercontent.com/113513376/218345929-2506cc15-2d7a-44ef-80bb-68216b21a9e3.png)

I'll use the key as pin on the web app works
![image](https://user-images.githubusercontent.com/113513376/218345993-ca4b2069-61f5-4c5c-9f64-e1d0164b6d93.png)

This machine doesn't require rooting it just bypass the login form and reverse engineer the apk file

```
Flags:
Flag43: c6572ee2d23ca613ea0afcc089d22a4f4b52af01
Flag44: 022642b57e3eaa4daee6dec155b991f8fae58925
Flag45: a77d62e6af325cf1089ea9d56228df9590b1c366
```

Write-ups have been authorized for this machine by the PwnTillDawn Crew! You can access the box using this link [Wizlynx](https://www.wizlynxgroup.com/) and [PwntillDawn](https://online.pwntilldawn.com/)

And we're done

<br> <br>
[Back To Home](../../index.md)
