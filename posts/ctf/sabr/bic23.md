### BIC 2023 WINTER CTF 

### Description: This is a CTF hosted by Blacks In Cybersecurity

##### It was a fun challenge which I focused only on solving all pwn challenges but sadly they only brought one pwn challenge. I was able to solve the pwn challenge with an easy reverse engineering chall. Lets get straight to it

#### Reverse Engineering 

Firstly i'll do the easy reverse engineering challenge 

Basic file checks

```
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ file chall       
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=32b061e72f3608b65f0649e1f97e7d5d5b049b87, for GNU/Linux 3.2.0, stripped
```

From the file check we know that its a x64 binary and its statically linked (meaning that all libraries that the executable needs are integrated inside) and also is stripped ( meaning that we won't be able to see the function names)

Lets run it to know what it does

```
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ ./chall       
/===========================================================================\
|               Welcome to BIC Winter CTF \0/                               |
+===========================================================================+
[ERROR] Login information missing
Usage: ./chall <username> <password>
```

It requires passing two parameters which are username and password

Since i don't know it lets decompile the binary using ghidra

After decompiling it i'll click on the entry function
![image](https://user-images.githubusercontent.com/113513376/221995246-1f50e94a-4f9d-4687-b9c7-6b8176d1ccb8.png)

Then i'll click on `FUN_004018c5` which is going to be the main function
![image](https://user-images.githubusercontent.com/113513376/221995630-55f448e4-f7ed-4712-8952-e5f497ce7325.png)

We can see the decompiled code 

```
undefined8 FUN_004018c5(int argc,undefined8 *argv)

{
  undefined uVar1;
  int compare;
  undefined8 uVar2;
  long lVar3;
  long lVar4;
  ulong uVar5;
  long in_FS_OFFSET;
  ulong local_c8;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined local_a8;
  undefined local_98 [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_b8 = 0x645f736b316c4c7a;
  local_b0 = 0x495f6730545f6d34;
  local_a8 = 0;
  FUN_004017b5(
              "/===========================================================================\\\n|                Welcome to BIC Winter CTF \\0/                               |\n+========== =================================================================+\n"
              );
  if (argc == 3) {
    FUN_004017b5(" ~> Verifying.");
    FUN_00401805(3);
    compare = FUN_00401130(argv[1],"hacker");
    if (compare == 0) {
      lVar3 = FUN_00401180(argv[2]);
      lVar3 = FUN_0041ff20(lVar3 + 1);
      FUN_00401020(lVar3,argv[2]);
      local_c8 = 0;
      while( true ) {
        uVar5 = FUN_00401180(lVar3);
        if (uVar5 >> 1 <= local_c8) break;
        uVar1 = *(undefined *)(local_c8 + lVar3);
        lVar4 = FUN_00401180(lVar3);
        *(undefined *)(local_c8 + lVar3) = *(undefined *)(lVar3 + (lVar4 - local_c8) + -1);
        lVar4 = FUN_00401180(lVar3);
        *(undefined *)((lVar4 - local_c8) + -1 + lVar3) = uVar1;
        local_c8 = local_c8 + 1;
      }
      FUN_00401805(3);
      compare = FUN_004010d0(lVar3,&local_b8,0x11);
      if (compare == 0) {
        FUN_004017b5("Correct!\n");
        FUN_004017b5("Welcome back!\n");
        FUN_0040ba90(local_98,0x80,"bicWC{%s}\n",argv[2]);
        FUN_004017b5(local_98);
      }
      else {
        FUN_004017b5("ACCESS DENIED\n");
        FUN_004017b5(" ~> Incorrect password\n");
      }
      uVar2 = 0;
    }
    else {
      FUN_004127f0(10);
      FUN_004017b5("ACCESS DENIED\n");
      FUN_004017b5(" ~> Incorrect username\n");
      uVar2 = 1;
    }
  }
  else {
    FUN_00412650("[ERROR] Login information missing");
    FUN_0040b9c0("Usage: %s <username> <password>\n",*argv);
    uVar2 = 1;
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    FUN_00452730();
  }
  return uVar2;
}
```

Well thats some confusion goin on here 😹. Anyways looking at the code we see that some hex values are stored in two variable then it checks if argv[1] that means the argument one i.e the username is equal to password 

Lets confirm it bypassing in `hacker` as argv[1] with a random pass as argv[2]

```
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ ./chall hacker lol             
/===========================================================================\
|               Welcome to BIC Winter CTF \0/                               |
+===========================================================================+
 ~> Verifying.......ACCESS DENIED
 ~> Incorrect password
```

We get incorrect password. I will decode the value stored in variable local_b8 and local_b0 respectively using xxd

```
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ echo 0x495f6730545f6d34 | xxd -r -p                        
I_g0T_m4                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ echo 0x645f736b316c4c7a | xxd -r -p      
d_sk1lLz
```

We get its ascii value now lets join it together and passing as the second parameter which is the password

```
┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ python3
Python 3.11.1 (main, Dec 31 2022, 10:23:59) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> a = 'I_g0T_m4'
>>> b = 'd_sk1lLz'
>>> "".join(a+b)
'I_g0T_m4d_sk1lLz'
>>>

┌──(mark㉿haxor)-[~/Desktop/CTF/WinterCon/rev]
└─$ ./chall hacker I_g0T_m4d_sk1lLz
/===========================================================================\
|               Welcome to BIC Winter CTF \0/                               |
+===========================================================================+
 ~> Verifying.......Correct!
Welcome back!
bicWC{I_g0T_m4d_sk1lLz}
```

And thats all for it the flag is `bicWC{I_g0T_m4d_sk1lLz}`




