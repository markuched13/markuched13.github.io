### Binary Exploitation

### Source: PICOCTF

### Basic File Checks

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/wine]
└─$ file vuln.exe 
vuln.exe: PE32 executable (console) Intel 80386, for MS Windows
```

Its a windows executable

Source code is given

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void win(){
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("flag.txt not found in current directory.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

void vuln()
{
  printf("Give me a string!\n");
  char buf[128];
  gets(buf);
}

int main(int argc, char **argv)
{

  setvbuf(stdout, NULL, _IONBF, 0);
  vuln();
  return 0;
}
```

We can see the program prints our give me a string then receives out input using the get() call which is vulnerable to buffer overflow

So obviously our goal is to return to the win function

Unlike using gdb to debug i don't know if that is possible 

But in this case i'll use `Immunity Debugger`

So i'll hop on to my windows box and run the binary one my windows machine
![image](https://user-images.githubusercontent.com/113513376/217090561-3582499d-757e-4bca-b0b5-2ace6694ae01.png)

So with this i'll attach the process on immunity debugger
![image](https://user-images.githubusercontent.com/113513376/217090666-8a33b8d7-ca7b-45ee-86ae-ef7c221874eb.png)

Now i will generate a msf pattern

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/wine]
└─$ msf-pattern_create -l 250
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2A
```

Now this is the string i'll give the binary as input

The program crashes 
![image](https://user-images.githubusercontent.com/113513376/217091167-08e3c036-d782-4d4f-995b-f7af604e54c9.png)

So with this i can use the mona plugin to get the offset

```
Command: !mona findmsp -distance 250
```
![image](https://user-images.githubusercontent.com/113513376/217091847-883f5faa-62cc-496e-a898-347bf7bb0dcb.png)

Here's the important part

```
Log data, item 16
 Address=0BADF00D
 Message=    EIP contains normal pattern : 0x37654136 (offset 140)
```

Cool the offset is 140

Now i'll get make the exploit script


