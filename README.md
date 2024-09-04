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

To bypass ASLR, we could take two approaches, and we will demonstrate both:
1. Defeating ASLR with a `leak`. Usually `ASLR` leaks are another type of vulnerability, but in our case it's easy - we can read the return address from the stack using our awesome read primitive.
2. Doing a partial write. This approach is sometimes very tailored to specific situations - but I'd like to demonstrate it for completeness.


