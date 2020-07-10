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

First I like to find out how much I have to feed the program before I start overwriting the eip, so I have script that creates arbitrarily long strings of the alphabet repeating that I can feed programs to see where it crashes. My strings look like "AAAAAAAABBBBBBBBCCCCCCCC....", and I can feed this into gdb and see what we are trying to return to.

pwndbg shows us:
```
$ gdb badchars
$ run < alpha
 RBP  0x4545454545454545 ('EEEEEEEE')
 RSP  0x7fffffffdfa8 ◂— 0x4646464646464646 ('FFFFFFFF')
 RIP  0x4009de (pwnme+233) ◂— ret    
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x4009de <pwnme+233>    ret    <0x4646464646464646>
```
So we are trying to return in the F's spot, so I can count that up and see that we need 40 bytes to overwrite our return address. 

Next we can start exploring the code by listing all of the functions that radare2 can find. 

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
$ s sym.imp.system 
$ pdf 
CALL XREF from sym.usefulFunction @ 0x4009e8
```

if we set r2 to main and follow some of these functions we see that main calls pwnme, pwnme calls fgets which is where we will enter our input, afterwards nstrlen checks that our input is less than 0x200 bytes long, returns to pwnme, pwnme calls checkBadchars,  it checks to ensure you haven't added any bad characters, returns to pwnme, and pwnme tries to return to main, but if we do our job right we should be able to start our ROPchain here. Now we just need to figure out where we are going to go. 

The first thing we can realize is that we have a call to system in our code, so if we have a useful string like /bin/sh or cat in our binary we may be able to easily just call system with that string and win. However, we don't seem to have any of those strings after searching using objdump, radare2, and strings. So now we need to see if we have anywhere in our binary that we can write to where we can store our string.

If we run gdb and check the virtual memory pages we will see:
```
$ gdb badchars
$ start
$ vmmap
 Data : 0x601000           0x602000  rw-p
```

So we know that we have a call to system(), we have a place that we can write our string to, and that we can't write certain characters into our ROPchain. Now we just need to exploit this. 

### How are we going to exploit it?

Now that we have decided to write our string to memory and try to call system to run it, we need to start looking for some ROP gadgets that can get us there. We are also given a hint by ROPE that we may be able to use xor to help us out in some way. If you understand XOR then you know that when you xor a value with a key then you will be able to get back to the original value by xor'ing the output with the key again. So for this exploit we will need to create an xor'ed string that we can write to memory, write it to memory, xor that string to bring it back to it's original value, and then call system. Since we were given two functions labled "useful" then we may as well disassemble them and see if there is anything in them that we can use. 

So using radare2 again we can see: 
```
$ aaaa
$ aaf
$ s sym.usefulFunction
$ pdf
0x004009df      55             push rbp
0x004009e0      4889e5         mov rbp, rsp
0x004009e3      bf2f0c4000     mov edi, str.bin_ls         ; 0x400c2f ; "/bin/ls" ; const char *string
0x004009e8      e803fdffff     call sym.imp.system         ; int system(const char *string)
0x004009ed      90             nop
0x004009ee      5d             pop rbp
0x004009ef      c3             ret

$ s loc.usefulGadgets
$ pdf
0x00400b30      453037         xor byte [r15], r14b
0x00400b33      c3             ret
```

So just from those two functions we have our system gadget and our xor gadget. So  now we can use ropper to find some good pop and mov gadgets. 
```
$ ropper --file badchars --search mov
...
0x0000000000400b34: mov qword ptr [r13], r12; ret; 
...
$ ropper --file badchars --search pop
...
0x0000000000400b42: pop r15; ret; 
0x0000000000400b40: pop r14; pop r15; ret; 
0x0000000000400b3b: pop r12; pop r13; ret; 
0x0000000000400b39: pop rdi; ret; 
...
```

I picked these gadgets to show because for our xor and mov gadgets we need matching pop calls and a rdi pop for our call to system. 

So with these gadgets and our initial 40 bytes that we need to overwrite the return address, we will be able to write our xor'ed string to the start of data's memory, xor it once it's in memory to get it back to where we want it, and then pop the address for our string into rdi and call system. 

### The exploit

I have written a python script "solve.py" that will xor "/bin/sh", add a null byte to the end, create all of our needed gadgets, combine them into the necessary payload, then send them to the running process and create an interactive shell. Enjoy the completed challenge and read that flag.txt