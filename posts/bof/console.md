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
