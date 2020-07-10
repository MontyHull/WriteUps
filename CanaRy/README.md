# CanaRy from picoCTF 2019

This time we added a canary to detect buffer overflows. Can you still find a way to retreive the flag?

## Tools Used 

- pwntools
- radare2
- pwndbg
- objdump

### Initial exploration

For this challenge we are given the source code, the compiled binary, and a directory on their server where we can run the code to actually get the flag. The first thing that should jump out is that the name of the challenge is CanaRy so I am going to assume that we will be trying to bypass some form of stack canary in order to win this. 

We can start with our usual security check:
```
$ checksec
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

So, oddly enough, the only traditional protection turned off is stack canaries. So we can't just throw shellcode on the stack since NX is enabled, and trying to jump to other functions may be a little more difficult thanks to RELRO and PIE.

If we run the binary, we get: 
```
$ ./vuln
Please enter the length of the entry:
> 4
Input> AAAA
Ok... Now Where's the Flag?
```

So we are asked how much we want to write, then for our input. What if we input a larger payload though. 
```
$ ./vuln
Please enter the length of the entry:
> 50
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** Stack Smashing Detected *** : Canary Value Corrupt!
```

So now we see that they have implemented their own canary somehow. Now let's look at their code to see if we can find any buffers, their sizes, and any other useful information. 

```C
#define BUF_SIZE 32
#define KEY_LEN 4
...
void display_flag() {}
...
void vuln(){
   char canary[KEY_LEN];
   char buf[BUF_SIZE];
...
printf("Input> ");
read(0,buf,count);

if (memcmp(canary,key,KEY_LEN)) {
  printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
  exit(-1);
}
printf("Ok... Now Where's the Flag?\n");
```

So from these snippets we can tell that our buffer that we are writing to is 32 bytes long, the canary that we accidently overwrote is only 4 bytes long, there is a display_flag() function that we need to call, and that if we overwrite our canary with the wrong values then we will immediately exit, and if we don't then we will just return to main. 

### Exploitable piece of code

So we know that before we can overwrite our return address we will need to get past the canary. To get to the canary we will need to write 32 bytes of input, then find a way to overwrite the canary with whatever it may be, then continuing until we have overwritten the return address to display_flag(). So to start we can get the address of that function with radare2. 

Running r2 we get:
```
$ r2 ./vuln
$ aaaa
$ afl
...
0x000007ed    3 141          sym.display_flag
0x0000087a    3 122          sym.read_canary
0x000008f4    9 273          sym.vuln
```

Now if we remember the security check, PIE is turned on, so our address will change each run, but if we stick with this and run our script a few times, we should be able to land a hit and jump to the right spot. 

### How are we going to exploit it?

Now that we know we have to jump to another function, and that we have to defeat a canary to get there we need to set up a way to check if we can overwrite the canary ourselves. If we try to get right up to the canary and then 1 byte into it we can see that we may be able to only change a byte of the canary at a time. 

```
$ ./vuln 
Please enter the length of the entry:
> 32
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ok... Now Where's the Flag?

$ ./vuln 
Please enter the length of the entry:
> 33
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
** Stack Smashing Detected ** : Canary Value Corrupt!
``` 

So if we create a pwntools script to loop through all of the printable characters we can search for an instance when we overwrite the first byte with the right byte. If we do then we will get the printed message "Ok... Now Where's the Flag?" which we can search for in our recieved text and break on. We know that our canary is only four bytes, so if we run this loop four times we should be able to slowly build up our canary. Now that we have our canary we can look to see how far away from our return address we are.

Using objdump to disassemble the vuln binary we can see that: 
```
$ objdump -D vuln | less
 992:   50                      push   %eax
 993:   8d 45 d0                lea    -0x30(%ebp),%eax
 996:   50                      push   %eax
 997:   6a 00                   push   $0x0
 999:   e8 12 fc ff ff          call   5b0 <read@plt>
 ```

Which means that there is 0x30 or 48 bytes before the ebp, so we will need to write 52 bytes + 2 more for the address of our flag. 

### The exploit

Once we know the address of the flag function, our canary, and how far away from the return address we are, all we need to do is to start the process in a loop and continously try to land our return at the right place in order to print the flag. I have written a python script "solution.py" that will find the canary and then use it to get to the display_flag() function and win. 