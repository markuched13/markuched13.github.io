### Harvester HTB Apocalypse2021

### Binary Exploitation 

### TL;DR Solution: Use a format string to leak canary, piebase address & perform a ret2libc attack 

#### Basic File Checks

```
┌──(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/harvester]
└─$ file harvester 
harvester: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c38bca86a80d4c3750dba23da387213e5e8b96d4, not stripped
                                                                                                                                                                                            
┌──(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/harvester]
└─$ checksec --format=json --file=harvester | jq
{
  "harvester": {
    "relro": "full",
    "canary": "yes",
    "nx": "yes",
    "pie": "yes",
    "rpath": "no",
    "runpath": "yes",
    "symbols": "yes",
    "fortify_source": "no",
    "fortified": "0",
    "fortify-able": "2"
  }
}
```

We're working with a x64 binary and all protections are enabled 💀

Lets run it to know what it does
![image](https://user-images.githubusercontent.com/113513376/222261870-ee0c20ab-040d-49df-a58a-3e0345bdd441.png)
![image](https://user-images.githubusercontent.com/113513376/222261951-5a99e553-642d-4907-89cf-405efe793fd2.png)



