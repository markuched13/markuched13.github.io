<h3> PwnShop HackTheBox </h3>

#### Binary Exploitation

#### Basic File Checks

![image](https://user-images.githubusercontent.com/113513376/222904805-179dc0a7-3021-478b-8386-4394b3df5106.png)

We're working with a x64 binary and its is stripped

The protections enabled are NX and PIE and here's what they do:

```
1. NX(No-Execute) prevents shellcode injection to the stack and execution of the shellcode
2. PIE randomize memory addresses 
```

I'll run it to know what it does
![image](https://user-images.githubusercontent.com/113513376/222905603-7b91ebb0-84f5-4768-b0cb-37396cd76657.png)

Using ghidra i'll decompile the binary

From the entry function we can get the main function
![image](https://user-images.githubusercontent.com/113513376/222905636-b6b2d667-8dca-4bf8-bfde-acca877968bd.png)

The main function address is `FUN_001010a0`

Here's the decompiled code
![image](https://user-images.githubusercontent.com/113513376/222906045-12b70b66-7a79-4b65-9bae-5ed8bb7c323b.png)

```

undefined  [16] FUN_001010a0(void)

{
  int iVar1;
  ulong in_RCX;
  char cVar2;
  
  FUN_0010121e();
  puts("========= HTB PwnShop ===========");
  while( true ) {
    while( true ) {
      puts("What do you wanna do?");
      printf("1> Buy\n2> Sell\n3> Exit\n> ");
      iVar1 = getchar();
      getchar();
      cVar2 = (char)iVar1;
      if (cVar2 != '2') break;
      FUN_0010126a();
    }
    if (cVar2 == '3') break;
    if (cVar2 == '1') {
      FUN_0010132a();
    }
    else {
      puts("Please try again.");
    }
  }
  return ZEXT816(in_RCX) << 0x40;
}
```

We can see what it does:

```
1. Prints out the banner thingy
2. Gets our option and the available option is just 1,2 and 3
3. If 2 is chosen it calls the function for option2 same applies to 1 and 3
4. But if a given value is is not among the option it prints out please try again
```

Here's the decompiled function if option 1 is chosen
![image](https://user-images.githubusercontent.com/113513376/222906243-8bf10247-2393-4f36-834c-62028140338f.png)

```
void FUN_0010132a(void)

{
  undefined auStack72 [72];
  
  puts("Sorry, we aren\'t selling right now.");
  printf("But you can place a request. \nEnter details: ");
  read(0,auStack72,0x50);
  return;
}
```

From reading the code we can see that it receives our input and reads in 80 bytes of data in a 70 bytes buffer so there's a buffer overflow here

Here's the decompiled function if option 2 is chosen
![image](https://user-images.githubusercontent.com/113513376/222906380-a96098fd-ccc9-4010-a206-316e97b0b88f.png)

```

void FUN_0010126a(void)

{
  int iVar1;
  long lVar2;
  undefined4 *puVar3;
  byte bVar4;
  undefined4 auStack72 [8];
  undefined8 local_28;
  undefined4 *local_20;
  
  bVar4 = 0;
  local_20 = &DAT_001040c0;
  printf("What do you wish to sell? ");
  local_28 = 0;
  puVar3 = auStack72;
  for (lVar2 = 8; lVar2 != 0; lVar2 = lVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
  }
  read(0,auStack72,0x1f);
  printf("How much do you want for it? ");
  read(0,&local_28,8);
  iVar1 = strcmp((char *)&local_28,"13.37\n");
  if (iVar1 == 0) {
    puts("Sounds good. Leave details here so I can ask my guy to take a look.");
    puVar3 = local_20;
    for (lVar2 = 0x10; lVar2 != 0; lVar2 = lVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
    }
    read(0,local_20,0x40);
  }
  else {
    printf("What? %s? The best I can do is 13.37$\n",&local_28);
  }
  return;
}
```


Here's what it does:

```
1. It first receives our input which reads 31 bytes of our input and stores it in a 8bytes buffer
2. Our input is received again but this time it reads 8 byte of our input to and stores it in &local_28
```

So there's another buffer overflow in this part of the code

After i tried running the binary and just trying to overflow it i noticed if you feed in 8 bytes to the second input of option 2 it leaks some value
![image](https://user-images.githubusercontent.com/113513376/222906699-ef0a6ad3-c1bf-4943-b09f-29c939026fdf.png)


