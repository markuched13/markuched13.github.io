### Controller HackTheBox Apocalypse21

### Binary Exploitation

### Basic File Checks

```
└─$ file controller
controller: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e5746004163bf77994992a4c4e3c04565a7ad5d6, not stripped
                                                                                                                                                                 
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/controller]
└─$ checksec controller
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/controller/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We're working with a x64 binary which is dynamically linked and not stripped

Looking at the protections we see that it has just `FULL RELRO` making GOT overwrite impossible and `NX ENABLED` making ret2shellcode not possible

I'll run the binary to know what it does

```
└─$ ./controller           

👾 Control Room 👾

Insert the amount of 2 different types of recources: 1 1
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 1
1 + 1 = 2
Insert the amount of 2 different types of recources: 2 10
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
2 * 10 = 20
Insert the amount of 2 different types of recources: ^C
```

We see that its some sort of calculator 

Using ghidra i'll decompile the binary

Here's the decompiled main function

```

undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  welcome();
  calculator();
  return 0;
}
```

It calls welcome() function

Here's the decompiled welcome() function

```
void welcome(void)

{
  color(&controlroom,&red,&bold);
  return;
}
```

Nothing really much it just deals with the colour welcome banner

Main function also calls calculator()

```
void calculator(void)

{
  char input [28];
  int value;
  
  value = calc();
  if (value == 0xff3a) {
    printstr("Something odd happened!\nDo you want to report the problem?\n> ");
    __isoc99_scanf(%s,input);
    if ((input[0] == 'y') || (input[0] == 'Y')) {
      printstr("Problem reported!\n");
    }
    else {
      printstr("Problem ingored\n");
    }
  }
  else {
    calculator();
  }
  return;
}
```

So here's what this does

```
1. It calls the calc() function
2. It checks if the value the calc() function returns is equal to 0xff31 (-198)
3. IF the check is meet it receives our input using scanf and store in a buffer that can hold up to 28bytes
4. If the first index of our character is y or Y it prints problem reported
5. Else it prints problem ignored
6. Else the calculator function just keeps looping
```

Here's the decompiled code for calc()

```

uint calc(void)

{
  ushort uVar1;
  float fVar2;
  uint num2;
  uint num1;
  int menu;
  uint eval;
  
  printstr("Insert the amount of 2 different types of recources: ");
  __isoc99_scanf("%d %d",&num1,&num2);
  menu = ::menu();
  if ((0x45 < (int)num1) || (0x45 < (int)num2)) {
    printstr("We cannot use these many resources at once!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x69);
  }
  if (menu == 2) {
    eval = sub(num1,num2);
    printf("%d - %d = %d\n",(ulong)num1,(ulong)num2,(ulong)eval);
    return eval;
  }
  if (menu < 3) {
    if (menu == 1) {
      eval = add(num1,num2);
      printf("%d + %d = %d\n",(ulong)num1,(ulong)num2,(ulong)eval);
      return eval;
    }
  }
  else {
    if (menu == 3) {
      uVar1 = mult(num1,num2);
      eval = (uint)uVar1;
      printf("%d * %d = %d\n",(ulong)num1,(ulong)num2,(ulong)eval);
      return eval;
    }
    if (menu == 4) {
      fVar2 = (float)divi(num1,num2);
      eval = (uint)(long)fVar2;
      printf("%d / %d = %d\n",(ulong)num1,(ulong)num2,(long)fVar2 & 0xffffffff);
      return eval;
    }
  }
  printstr("Invalid operation, exiting..\n");
  return eval;
}
```

Here's what the cde does

```
1. It asks for 2 numbers 
2. A check is done to know if any of the given number is less than 0x45 
3. Then it prints the options out
4. If the add function is chosen it basically just sums up the two numbers together same applies with other calculation options
5. If an integer is not given it will print invalid operation
```

From this we know that the aim is to firstly want to bypass the check that does a comparision of the value stored in check to -198

But before we do that we need to firstly make the calculation value to be equal to -198 

Since we are not given opportunity to input a large number we would have to find a way to get a number that when calculated gives -198

And the value i got is `-18 * 11 = -198`

With this we will bypass the if check then for the buffer overflow we know that scanf didn't specify the amount of bytes to write in 

Leveraging that will lead to a buffer overflow 

Now i'll run the binary to trigger segfault

```
