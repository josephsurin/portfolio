---
path: /posts/2022-06-10-greyctf-2022-catino-writeup
title: GreyCTF 2022 - Catino
date: 2022-06-10
tags: ctf,writeup,crypto
---

# Catino

> Our cat is cute right!
> 
> `nc challs.nusgreyhats.org 10520`

`main.py`:

```py
#!/usr/bin/env python3

from secrets import randbits
from decimal import Decimal, getcontext

FLAG = '<REDACTED>'

ind = 100
randarr = []
maxRound = 5000
winTarget = 100000
winIncr = 1000

getcontext().prec = maxRound + 1000

def prep():
    global randarr
    print("\nGenerating random numbers....", flush=True)
    n = Decimal(randbits(2048))
    p = Decimal(1/4)
    k = str(n**p).split('.')[1]
    randarr = list(k)
    print("Generation complete!\n", flush=True)


def nextRand():
    global ind
    assert ind < len(randarr)
    res = int(randarr[ind])
    ind += 1
    return res


def menu():
    print("Hey there, I am catino! Meowww ~uwu~")
    print("Play a game with me and win the flag!\n")

    print("Game rule:")
    print("1. You start with $0")
    print("2. On each round, Catino choose a single digit secret number (0-9)")
    print("3. You try to guess Catino secret's number")
    print(f"4. If the guessed number matches the secret, then you earn ${winIncr}")
    print("5. If the guessed number does not match the secret, then you lose all of your money!")
    print(f"6. You win when you have ${winTarget}!")
    print(f"7. The game ends forcefully when the number of round exceeds {maxRound}", flush=True)

if __name__ == "__main__":
    menu()
    prep()

    round = 0; wrong = 0; player = 0

    while (player < winTarget and round < maxRound):
        round += 1
        print(f"Round: {round}")
        userIn = int(input("Guess the number (0-9): "))
        num = nextRand()
        if (num == userIn):
            print(f"You got it right! it was {num}")
            player += winIncr
        else:
            print(f"You got it wrong... it was {num}")
            player = 0
        print(f"You have ${player} left")
    
    if (player >= winTarget):
        print("Congratulations you are now rich! \(★ω★)/")
        print(FLAG)
    else:
        print("Sokay.. Try again next time (っ´ω`)ﾉ(╥ω╥)")
```

## Challenge Overview

This challenge revolves around a number guessing game where the numbers we must guess are generated by taking digits from the decimal part of the fourth root of some large number. There are a total of up to 5000 rounds and to get the flag we must correctly guess the digit for 100 consecutive rounds. After each round, we are told what was the correct digit. Essentially, we may obtain an approximation of the decimal part up to 4900 digits and need to compute the next 100 digits.

## Solution

There is a (famous?) [paper](https://dl.acm.org/doi/10.1145/800057.808681) which describes an approach to solving the problem we have in this challenge. The paper shows that the bits of [algebraic numbers](https://en.wikipedia.org/wiki/Algebraic_number) are not random, and that given an approximation of an algebraic number, we may recover its [minimal polynomial](https://en.wikipedia.org/wiki/Minimal_polynomial_(field_theory)) (and hence, better approximations) using lattice reduction techniques. An algebraic number is a number that is a root of a non-zero univariate polynomial with rational coefficients. Let's show that the digits we are trying to recover form an algebraic number.

### $k$ is an algebraic number

Let $n$ be the randomly generated 2048 bit number. Write $n^{\frac{1}{4}} = a + k$ where $a \geq 1$ and $k < 1$. Here, $a$ represents the whole part of $n^{\frac{1}{4}}$ and $k$ is the decimal part. Then,

$$
\begin{aligned}
    n^{\frac{1}{4}} &= a + k \\
    \implies n &= (a + k)^4 \\
    \implies n &= a^4 + 4a^3k + 6a^2k^2 + 4ak^3 + k^4
\end{aligned}
$$

And so,

$$
a^4 + 4a^3k + 6a^2k^2 + 4ak^3 + k^4 - n = 0
$$

Now, consider the polynomial $f \in \mathbb{Z}[x]$ given by

$$
f(x) = x^4 + 4ax^3 + 6a^2x^2 + 4a^3x + a^4 - n
$$

This polynomial has rational coefficients (since $a$ is an integer), and more importantly, has $k$ as a root. Therefore, $k$ is an algebraic number. Now, let's see how to recover $f$ given an approximation of $k$.

### Recovering $f$

We want to recover $f$ because it will allow us to calculate $k$ up to arbitrary precision. Suppose we know an approximation $k_0$ of $k$ (say, the first $D = 4900$ digits[^1]). The key idea is that $f(k_0) \approx 0$, i.e.,

$$
f(k_0) = k_0^4 + 4ak_0^3 + 6a^2k_0^2 + 4a^3k_0 + a^4 - n \approx 0
$$

This is a nice property because it means lattices are likely around the corner! Consider the lattice with basis given by the rows of $\mathbf{M}$:

$$
\mathbf{M} =
\begin{bmatrix}
    \lfloor 10^D k_0^4 \rfloor \\
    \lfloor 10^D k_0^3 \rfloor & 1 \\
    \lfloor 10^D k_0^2 \rfloor & & 1\\
    \lfloor 10^D k_0 \rfloor   & & & 1\\
    \lfloor 10^D \rfloor     & & & & 1\\
\end{bmatrix}
$$

Notice that the linear combination

$$
\mathbf{t} = (1, 4a, 6a^2, 4a^3, a^4 - n)
$$

generates the lattice point

$$
\mathbf{a} = (s, 4a, 6a^2, 4a^3, a^4 - n)
$$

(i.e. $\mathbf{t} \mathbf{M} = \mathbf{a}$) where $s$ is relatively small, depending on how good of an approximation $k_0$ is. $s$ will dominate the length of $\mathbf{a}$ because of the scaling factor $10^D$, but it is still smaller than other non-zero lattice points. Omitting a proper analysis, we can conclude that LLL is likely to disclose $\mathbf{a}$ and hence we can recover $f$ by reading the coefficients off the entries of $\mathbf{a}$.

### Solving the challenge

Of course, Sage has a [function](https://doc.sagemath.org/html/en/reference/rings_standard/sage/arith/misc.html#sage.arith.misc.algdep) to do almost exactly what was described in the previous section, so we can use that to implement the solution. Since we need to gather close to 4900 digits, we need to send the guesses and parse the responses in batches to avoid the server timeout.

```py
from pwn import *
from decimal import Decimal, getcontext
from sage.arith.misc import algdep

getcontext().prec = int(6000)

conn = remote('challs.nusgreyhats.org', 10520)
conn.recvuntil(b'Generation complete!')

k = '0.'
payload = b'\n'.join([b'0']*100)
conn.recvuntil(b'(0-9):')
for _ in range(49):
    conn.sendline(payload)
    lines = conn.clean().splitlines()
    for l in lines:
        if b'it was ' in l:
            k += l.decode().strip().split('it was ')[1]

f = algdep(Reals(16278)(k), 4)
k_full = f.change_ring(Reals(16800)).roots()[1][0]
k_next = str(k_full)[2+4900:2+4900+100]

for d in k_next:
    conn.sendline(d.encode())

conn.interactive()
```

`grey{FunFact_OurGreyCatIsActuallyABlackCat_LFP9eux3884hd2ag}`

[^1]: In the challenge we actually only have access to the digits after the first 100 digits of $k$, but it's not hard to modify our arguments here to work with that. For simplicity, we assume we just have an approximation of $k$ starting from the first digit.