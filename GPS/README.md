# GPS from picoCTF 2018

You got really lost in the wilderness, with nothing but your trusty gps. Can you find your way back to a shell and get the flag?

## Tools Used 

- pwntools
- shellstorm (http://shell-storm.org/shellcode/files/shellcode-806.php)

### Initial exploration

For this challenge we are given the source code, the compiled binary, and a directory on their server where we can run the code to actually get the flag. Thanks to the description of the challenge we can assume that we are going to be trying to get a shell from this program.

Let's start with running checksec:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

From this we know that trying to ROP around will be a little dificult with a canary turned on, but we have an executable stack with no PIE, so we should be able to inject some shellcode wherever we get input, and hopefully pico will give us a way to execute it. 

If we run the binary, we get:
```
GPS Initializing..........Done
Acquiring satellites.Satellite 0..Done
Satellite 1......Done
Satellite 2.....Done

GPS Initialized.
Warning: Weak signal causing low measurement accuracy

We need to access flag.txt.
Current position: 0x7ffff56148e3
What's your plan?
> AAAA
Where do we start?
> AAAA
Segmentation fault (core dumped)
```

So The program takes two inputs and seems to segfault if it doesn't get exactly what it wants. We could break open a debugger and look at it, but why overburden ourselves if we are given source code. 

In the source code we can see:
```
#define GPS_ACCURACY 1337

typedef void (fn_t)(void);

void initialize() {}
void acquire_satellites() {}

void *query_position() {
      char stk;
      int offset = rand() % GPS_ACCURACY - (GPS_ACCURACY / 2);
      void *ret = &stk + offset;
      return ret;
}

int main() {
    char buffer[0x1000];
    printf("We need to access flag.txt.\nCurrent position: %p\n", query_position());

    printf("What's your plan?\n> ");
    fgets(buffer, sizeof(buffer), stdin);

    fn_t *location;

    printf("Where do we start?\n> ");
    scanf("%p", (void**) &location);

    location();
}
```

Upon looking through the code we can see that initialize() and acquire_satellites() are both just fluff code that do not seem to do anything meaningful, we have a defined value of 1337, query_position() will create some random number between 0 and 668 and then add that to the address of a random variable and set it to a void pointer which we return to main. Once back in main we get to input our plan into a buffer that is 0x1000 bytes long, a function pointer is created, and then we get to wrtie to that pointer where we want to start, then it is called. 

### Exploitable piece of code

Since we are given a huge buffer that we can write to, and then a function pointer that we can write to and we know will get called, all we need to do is write some shellcode into the buffer and find a way to get our function pointer to point to that shellcode. Since we don't need any particular address from this binary there isn't any need to disassemble it. 

### How are we going to exploit it?

Since when we run this code we are given the address of a variable that is on the stack + up to 669 bytes, we should be able to use that address, plus a pretty long NOP sled to easily slide into our shell code. Since our buffer is 4096 bytes long, We really can make our sled just about as long as we want 

### The exploit

I have a python script "solution.py" that connects to the remote server, sets up a payload with 3000 NOPs and some shellcode, reads in the what the socket is printing until we get our current location, we add 1000 to that location to hopefully get us onto our sled, we send our payload into the buffer, we then ask to start at our guessed location, and if everything works the way it should you will have an interactive terminal now. 