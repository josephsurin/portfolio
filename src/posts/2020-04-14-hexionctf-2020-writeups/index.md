---
path: /posts/2020-04-14-hexionctf-2020-writeups
title: HexionCTF 2020 Writeups
date: 2020-04-14
tags: ctf,infosec,writeup,crypto
---

Writeup for `SSS` crypto challenge from HexionCTF 2020. This was the only crypto chall (out of 3) that I found interesting. The first one was a standard XOR challenge, and the other one was an RSA LSB oracle.

- crypto
    - [SSS](#sss)

---

# SSS <a name="sss"></a>

## SSS (908pts)

> Math is so beautiful and can always be used for cryptographic encryption!
> 
> `nc challenges1.hexionteam.com 5001`
> 
> Author: Yarin

`sss.py`:

```python
from Crypto.Util.number import bytes_to_long, getPrime
from random import randint
from secret import flag

MIN = randint(0x30, 0x40)
P = 2**521 - 1

def eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x"""
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def main():
    poly = [bytes_to_long(flag.encode())]
    poly.extend(set([randint(1, P - 1) for i in range(MIN)]))
    print("┌───────────────┐")
    print("│ SSS Encryptor │")
    print("└───────────────┘")
    print("Enter text to encrypt, leave empty to quit.")
    while True:
        data = input(">>> ")
        if bytes_to_long(data.encode()) % P == 0:
            break
        print(eval_at(poly, bytes_to_long(data.encode()), P))  

if __name__ == "__main__":
    main()
```

### Solution

We are presented with some cryptosystem that encrypts a message $m$ by evaluating the polynomial $p(m)$ with $p(x) \in \mathbb{F}_P[x]$. The polynomial's constant term is the flag, and the polynomial will have up to 64 terms. The oracle gives us the ability to encrypt any number of messages, with the constraint that the message cannot be the value of $P$ or a multiple of $P$. If we were allowed to send $P$, the evaluation of the polynomial at this value would simply return the constant term (i.e. the flag).

We can then set the coefficients of the polynomial $p$ as our unknowns. We write

$$p(x) = a_0 + a_1x + a_2x^2 + \cdots + a_{63}x^{63}$$

where $a_0$ is the flag.

It is clear that if we have as many pairs of messages and their encryptions $(x, p(x))$ as the number of coefficients in the polynomial, we can solve the system of equations and recover the coefficients. For example, if we know $p(1) = v_1$, then we can write

$$a_0 + a_1 + a_2 + \cdots + a_{63} = v_1$$

similarly, if we know $p(2) = v_2$, then we can write

$$a_0 + 2a_1 + 2^2a_2 + \cdots + 2^{63}a_{63} = v_2$$

We can then write the equations $p(1) = v_1, p(2) = v_2, \ldots, p(64) = v_{64}$ in matrix form:

$$\begin{bmatrix} 1 & 1 & 1^2 &\ldots & 1^{63} \\ 1 & 2 & 2^2 & \ldots & 2^{63} \\ \vdots & \ddots & & & \vdots \\ 1 & 64 & 64^2 & \ldots & 64^{63} \end{bmatrix}\begin{bmatrix} a_0 \\ a_1 \\ \vdots \\ a_{63} \end{bmatrix} = \begin{bmatrix} v_1 \\ v_2 \\ \vdots \\ v_{63} \end{bmatrix}$$

So once we get the values $(x, p(x))$, we simply need to solve for the coefficient vector. This can easily be done by taking the inverse of the big matrix on the left and left multiplying it with the values matrix on the right hand side of the equation. That is,

$$\begin{bmatrix} a_0 \\ a_1 \\ \vdots \\ a_{63} \end{bmatrix} = \begin{bmatrix} 1 & 1 & 1^2 &\ldots & 1^{63} \\ 1 & 2 & 2^2 & \ldots & 2^{63} \\ \vdots & \ddots & & & \vdots \\ 1 & 64 & 64^2 & \ldots & 64^{63} \end{bmatrix}^{-1}\begin{bmatrix} v_1 \\ v_2 \\ \vdots \\ v_{63} \end{bmatrix}$$

Implementing this with [sage](https://www.sagemath.org/) is the way to go as we can easily specify that values are elements of $\mathbb{F}_P$ and it'll automatically perform all operations within the field.

Note: I was having issues asking for the decryption of the newline byte so in the implementation, I ask for the encryption of `\x0e` up to `\x4d`. The theory is the exact same.

We use this script to get the value pairs:

```python
from pwn import remote
from Crypto.Util.number import long_to_bytes

conn = remote('challenges1.hexionteam.com', 5001)

V = []

for i in range(0xe, 0x40+0xe):
    conn.recvuntil(b'>>> ')
    conn.sendline(long_to_bytes(i))
    enc = int(conn.recvline().strip())
    print(enc)
    V.append(enc)

open('vs.py', 'w').write('V = ' + str(V))
```

And then to solve the challenge:

```python
from Crypto.Util.number import *
from vs import V

P = pow(2,521) - 1
F = GF(P)

xvals = list(range(0xe, 0x40+0xe))
V = vector(F, V)
M = Matrix(F, [[pow(x, i) for i in range(0x40)] for x in xvals])
poly = M.inverse()*V
print(long_to_bytes(poly[0]))
```

Flag: `hexCTF{d0nt_us3_shar3s_lik3_that}`
