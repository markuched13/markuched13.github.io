<h3> Console HackTheBox </h3>

### Binary Exploitation

### Basic File Checks

![image](https://user-images.githubusercontent.com/113513376/222837497-6171ddb0-b16b-48b4-8843-59ed5bab5e4f.png)

We're working with a x64 binary and all protections are disabled except NX which is No Execute generally it prevents shellcode injection to the stack and exection of the shellcode

I'll run it to know what it does
![image](https://user-images.githubusercontent.com/113513376/222837692-9c2975bf-d086-4188-8125-d611e211e0d8.png)

Nothing really interesting yet so i'll decompile the binary using ghidra

Take note that since this binary is a stripped binary we won't see function names

Looking at the entry function is the best way to get to the main function
![image](https://user-images.githubusercontent.com/113513376/222838986-8913003e-04aa-4f27-b36d-49b28d554d9c.png)

Now i'll click on the function that __libc_start_main is calling `FUN_00401397`

Here's now the main function
![image](https://user-images.githubusercontent.com/113513376/222839649-a3ea3b2b-a7c2-4398-aed8-7836cd73f0d8.png)

```
void FUN_00401397(void)

{
  char input [16];
  
  FUN_00401196();
  puts("Welcome HTB Console Version 0.1 Beta.");
  do {
    printf(">> ");
    fgets(input,16,stdin);
    program(input);
    memset(input,0,16);
  } while( true );
}
```

We can tell what it does:

```
1. It justs reads 16 bytes of our input to stdin 
2. Then it calls the other function called program (Note: I already renamed some variables in this function and i also did rename the function)
```

Here's the decompiled program() function
