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

int
main()
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

        return 0;
}
```

Well, let's analyze it!
- We have a "storage system" which is really just an array of 10 integers, where we can read and write freely.
- The index is never validated, which is very problematic - we can give either negative values or incides that are out-of-bounds!

