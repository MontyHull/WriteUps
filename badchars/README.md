# badchars from ROP Emporium 

An arbitrary write challenge with a twist; certain input characters get mangled before finding their way onto the stack. Find a way to deal with this and craft your exploit.

## Tools Used 

- radare2 
- pwndbg
- pwntools
- ropper 

### Initial exploration

Unlike the picoCTFs, ROP Emporium(ROPE) does not give you the source code for their challenges. However, we do know that we are going to need to ROP around the program and find a way to either pop a shell so that we can read the flag, or find a way to get the program to print the flag for us. We should always start out with checking the security on the file and then running it to see what kind of output we get. 

So checksec yields: 
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

So we know that we can's just spray shellcode onto the stack since NX is enabled, we don't have to worry about getting around a canary if we can overflow a buffer, we should be able to find a place in memory to write to if we need to since we only have partial RELRO, and our addresses shouldn't move around on us since PIE is turned off. 

Next if we run the program we get:
```
badchars by ROP Emporium
64bits

badchars are: b i c / <space> f n s
> AAAA

Exiting
```

So it looks like we can't write "b i c / <space> f n s" in our input, which will make /bin/sh, /bin/cat, or flag pretty hard to input. We will either have to find what we need inside our code or think of a different way to exploit the code. 

The only thing left to do is to see if we can crash the program with too much input:
```
Monty$ python -c "print('A'*1000)" | ./badchars 
badchars by ROP Emporium
64bits

badchars are: b i c / <space> f n s
> Segmentation fault (core dumped)
```

So it seems we will be able to work with the stack to ROP around easily. Next we will break open the binary to see where we can go. 

### Exploitable piece of code

I like to start exploring the code by listing all of the functions that radare2 can find. 

The commands and useful output that is yielded is:
```
$ r2 badchars
$ aaaa
$ aaf
$ afl
0x004008f5    4 234          sym.pwnme
0x004009f0    7 80           sym.nstrlen
0x00400a40    9 158          sym.checkBadchars
0x004009df    1 17           sym.usefulFunction
0x00400b30    1 4            loc.usefulGadgets
0x004006f0    1 6            sym.imp.system
```

if we set r2 to main and follow some of these functions we see that main calls pwnme, pwnme calls fgets which is where we will enter our input, afterwards nstrlen checks that our input is less than 0x200 bytes long, returns to pwnme, pwnme calls checkBadchars,  it checks to ensure you haven't set added any bad characters, returns to pwnme, and pwnme tries to return to main, but if we do our job right we should be able to start our ROPchain here. 


### How are we going to exploit it?

### The exploit