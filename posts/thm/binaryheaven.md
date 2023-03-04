<h3> Binary Heaven TryHackMe </h3>

![image](https://user-images.githubusercontent.com/113513376/222932877-e3270a1d-320f-4b3f-a947-4c7950798509.png)

We're given two files and the first question on thm asks:
![image](https://user-images.githubusercontent.com/113513376/222932929-37cb754e-16b5-4fd3-a03f-94bb2c6c6ec5.png)

```
What is the username?
```

Lets check the binary file type 
![image](https://user-images.githubusercontent.com/113513376/222932941-9c3602d8-5fab-4495-8b91-eb1b52a7ae03.png)

The first binary is an elf file which is dynamically linked an not stripped while the second is a go binary

Lets run the binary to know what it does
![image](https://user-images.githubusercontent.com/113513376/222932976-3e53edf6-575f-4b04-aaec-b1fc26578c81.png)

It asks for username so using ghidra i'll decompile the binary to know what it does
![image](https://user-images.githubusercontent.com/113513376/222933006-bdfd37b5-0cfa-4114-bf13-1e06b5ef6a2b.png)

```
undefined8
main(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
    undefined8 param_6)

{
  long lVar1;
  byte input [9];
  int i;
  
  lVar1 = ptrace(PTRACE_TRACEME,0,1,0,param_5,param_6,param_2);
  if (lVar1 == -1) {
    printf("Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n%22");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("\x1b[36m\nSay my username >> \x1b[0m");
  fgets((char *)input,9,stdin);
  i = 0;
  while( true ) {
    if (7 < i) {
      puts("\x1b[32m\nCorrect! That is my name!\x1b[0m");
      return 0;
    }
    if (*(int *)(username + (long)i * 4) != (char)(input[i] ^ 4) + 8) break;
    i = i + 1;
  }
  puts("\x1b[31m\nThat is not my username!\x1b[0m");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

We see what it does:

```
1. There's a debugger protection which prevents the binary from being run in a debugger
2. It asks for our input and stores it in input[]
3. A while loop is called which checks if the value of i is greater than 7 
4. If it is another if check is done and it checks if the username array is equal to our input which a bitwise operation (xor) is done 
5. If it isn't it prints out thats not my username
```

So here's the calculation done on the second if check

```
if int(username) + long(i) * 4 != (char(input[i]) ^ 4) + 8
```

And the value stored in the username array is this 
![image](https://user-images.githubusercontent.com/113513376/222933269-b0125387-2e7d-49bc-bc01-96b84f070eff.png)

```
                             username                                        XREF[3]:     Entry Point(*), main:00101202(*), 
                                                                                          main:00101209(R)  
        00104060 6b 00 00        undefine
                 00 79 00 
                 00 00 6d 
           00104060 6b              undefined16Bh                     [0]                               XREF[3]:     Entry Point(*), main:00101202(*), 
                                                                                                                     main:00101209(R)  
           00104061 00              undefined100h                     [1]
           00104062 00              undefined100h                     [2]
           00104063 00              undefined100h                     [3]
           00104064 79              undefined179h                     [4]
           00104065 00              undefined100h                     [5]
           00104066 00              undefined100h                     [6]
           00104067 00              undefined100h                     [7]
           00104068 6d              undefined16Dh                     [8]
           00104069 00              undefined100h                     [9]
           0010406a 00              undefined100h                     [10]
           0010406b 00              undefined100h                     [11]
           0010406c 7e              undefined17Eh                     [12]
           0010406d 00              undefined100h                     [13]
           0010406e 00              undefined100h                     [14]
           0010406f 00              undefined100h                     [15]
           00104070 68              undefined168h                     [16]
           00104071 00              undefined100h                     [17]
           00104072 00              undefined100h                     [18]
           00104073 00              undefined100h                     [19]
           00104074 75              undefined175h                     [20]
           00104075 00              undefined100h                     [21]
           00104076 00              undefined100h                     [22]
           00104077 00              undefined100h                     [23]
           00104078 6d              undefined16Dh                     [24]
           00104079 00              undefined100h                     [25]
           0010407a 00              undefined100h                     [26]
           0010407b 00              undefined100h                     [27]
           0010407c 72              undefined172h                     [28]
           0010407d 00              undefined100h                     [29]
           0010407e 00              undefined100h                     [30]
           0010407f 00              undefined100h                     [31]
```

we can see some hex values i'll automate the extraction of the second row
![image](https://user-images.githubusercontent.com/113513376/222933353-b64b38cb-89ac-4dd6-8428-ff99767db33d.png)
![image](https://user-images.githubusercontent.com/113513376/222933384-c98916da-8fe1-4e7b-9c78-cc47c4e7fd1f.png)

```
Command: cat username | awk -F " " '{print $2}' | tr "\n" " " | sed 's/ /","/g' | cut -d ":" -f 2
```

I'll save it in a file and rearrange it excluding the zero's
![image](https://user-images.githubusercontent.com/113513376/222933453-16615f26-63ea-4f61-850e-5e24e9c9178d.png)

Since its hex and we know that the calculation that is done to compare the user input is

```
(char(input[i]) ^ 4) + 8
```

Therefore the reverse of it will be

```
(chr(username - 8) ^ 4)
```

Using a python [script](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/thm/binary_heaven/username.py) i got the decoded value
![image](https://user-images.githubusercontent.com/113513376/222933644-d7a7cff0-9d79-4812-a083-41212c9d4515.png)

Submitting that works xD
![image](https://user-images.githubusercontent.com/113513376/222933718-19d05090-648b-4827-aa24-2b6a427f86f0.png)



