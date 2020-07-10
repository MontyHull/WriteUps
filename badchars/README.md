# badchars from ROP Emporium 

An arbitrary write challenge with a twist; certain input characters get mangled before finding their way onto the stack. Find a way to deal with this and craft your exploit.

## Tools Used 

- radare2 
- pwndbg
- pwntools
- ropper 

### Exploitable piece of code

Unlike the picoCTFs, ROP Emporium(ROPE) does not give you the source code for their challenges. However, we do know that we are going to need to ROP around the program and find a way to either pop a shell so that we can read the flag, or find a way to get the program to print the flag for us. We should always start out with checking the security on the file and then running it to see what kind of output we get. So checksec yields: 

'''
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
'''

So we know that we can's just spray shellcode onto the stack since NX is enabled, we don't have to worry about getting around a canary if we can overflow a buffer, we should be able to find a place in memory to write to if we need to since we only have partial RELRO, and our addresses shouldn't move around on us since PIE is turned off. 

Next if we run the program we get:

'''
badchars by ROP Emporium
64bits

badchars are: b i c / <space> f n s
> AAAA

Exiting
'''

### How are we going to exploit it?

### The exploit