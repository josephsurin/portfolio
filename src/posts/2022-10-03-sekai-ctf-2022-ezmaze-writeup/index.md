---
path: /posts/2022-10-03-sekai-ctf-2022-ezmaze-writeup
title: SekaiCTF 2022 - EZmaze
date: 2022-10-03
tags: ctf,infosec,writeup,crypto
---

I played in SekaiCTF 2022 with FrenchRoomba and we finished in 2nd place! Our team solved all of the crypto challenges which were all quite interesting. Thanks for the fun and well organised CTF :)

# EZmaze

**11 solves, 494 points**

> Can you escape the Maze? OwO
>
> Author: Utaha
> 
> `nc challs.ctf.sekai.team 3005`

`chall.py`:

```py
#!/usr/bin/env python3
import os
import random
from Crypto.Util.number import *

from flag import flag

directions = "LRUD"
SOLUTION_LEN = 64

def toPath(x: int):
    s = bin(x)[2:]
    if len(s) % 2 == 1:
        s = "0" + s

    path = ""
    for i in range(0, len(s), 2):
        path += directions[int(s[i:i+2], 2)]
    return path

def toInt(p: str):
    ret = 0
    for d in p:
        ret = ret * 4 + directions.index(d)
    return ret

def final_position(path: str):
    return (path.count("R") - path.count("L"), path.count("U") - path.count("D"))

class RSA():
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 65537
        self.d = pow(self.e, -1, self.phi)

    def encrypt(self, m: int):
        return pow(m, self.e, self.n)

    def decrypt(self, c: int):
        return pow(c, self.d, self.n)

def main():
    solution = "".join([random.choice(directions) for _ in range(SOLUTION_LEN)])
    sol_int = toInt(solution)
    print("I have the solution of the maze, but I'm not gonna tell you OwO.")

    rsa = RSA()
    print(f"n = {rsa.n}")
    print(f"e = {rsa.e}")
    print(hex(rsa.encrypt(sol_int)))

    while True:
        try:
            opt = int(input("Options: 1. Decrypt 2. Check answer.\n"))
            if opt == 1:
                c = int(input("Ciphertext in hex: "), 16)
                path = toPath(rsa.decrypt(c))
                print(final_position(path))
            elif opt == 2:
                path = input("Solution: ").strip()
                if path == solution:
                    print(flag)
                else:
                    print("Wrong solution.")
                    exit(0)
            else:
                print("Invalid option.")
                exit(0)
        except:
            exit(0)

if __name__ == "__main__":
    main()
```

## Challenge Overview

This is an RSA decryption oracle challenge, which is nicely packaged to be about finding the solution to a maze (although there isn't really a maze involved :p). On each connection, the server generates a 1024-bit RSA key pair as well as a "solution to the maze". The solution is a 128-bit number, and we are give its ciphertext under the RSA public key. Then, given access to an oracle which tells us the final position of the decrypted path corresponding to a provided ciphertext, we must recover the solution path to get the flag.

### toPath and toInt

In this challenge, a "path" is an arbitrary length string consisting only of the characters "LRUD" (left, right, up, down). Conversion between a path and an int is as simple as it gets: to go from an int to a path, we simply look at chunks of two bits (from left to right) and replace them according to the mapping:

```
00 -> L
01 -> R
10 -> U
11 -> D
```

For integers with odd bit length, a zero bit is prepended.

As an example, the integer `1337` has binary representation `10100111001` and so the corresponding path is `RRLDUR`:

```
 R R L D U R
010100111001
```

Conversion from a path to an int is simply the inverse of this.

### The Decryption Oracle

We can request the oracle as many times as we want. We provide it a ciphertext value $c$ and it will decrypt it to obtain $m = c^d \pmod n$. It then converts $m$ to a path and then gives us the final (x, y) coordinate one would end up at by following the path. For example, if the ciphertext we provided decrypts to the number `1337`, the oracle would return `(2, 0)`.

At first it might seem tricky to extract information out of this, but figuring it out is part of the fun :)

## Solution

The solution given here is an approach via LLL. The size of the solution path we are trying to recover is already so small (128 bits compared to the 1024-bit modulus), so we should only need a few more relations on the solution value to recover it.

The solution involves the hidden number problem, so for completeness, we give some background about HNP and EHNP here. Feel free to [skip it](#finding-the-hnp) if you're already familiar.

### The Hidden Number Problem

A (simplified) version of the hidden number problem can be stated as follows.

**(Hidden number problem).** Let $p$ be a prime and let $\alpha \in [1, p - 1]$ be a secret integer. Recover $\alpha$ given $m$ pairs of integers $\{ (t_i, a_i) \}_{i=1}^m$ such that

$$
\beta_i - t_i \alpha + a_i = 0 \pmod p
$$

where the $\beta_i$ are unknown and satisfy $|\beta_i| < B$ for some $B < p$.

For appropriate parameters, the HNP can be solved via a reduction to the closest vector problem. Consider the matrix with basis $\mathbf{B}$ given by

$$
\mathbf{B} =
\begin{bmatrix}
  p \\
  & p \\
  & & \ddots \\
  & &  & p \\
  t_1 & t_2 & \cdots & t_m & 1 / p \\
\end{bmatrix}
$$

By rewriting the HNP equations as $\beta_i + a_i = t_i \alpha + k_i p$ for integers $k_i$, we see that the linear combination $\mathbf{x} = (k_1, \ldots, k_m, \alpha)$ generates the lattice vector $\mathbf{x} \mathbf{B} = (\beta_1 + a_1, \ldots, \beta_m + a_m, \alpha / p)$. Defining $\mathbf{t} = (a_1, \ldots, a_m, 0)$ and $\mathbf{u} = (\beta_1, \ldots, \beta_m, \alpha / p)$, we notice that $\mathbf{x} \mathbf{B} - \mathbf{t} = \mathbf{u}$ where the length of $\mathbf{u}$ is bounded above by $\sqrt{m + 1} B$, whereas the lattice determinant is $p^{m-1}$. Therefore, we can reasonably expect an approximate CVP algorithm to reveal the vector $\mathbf{u}$ from which we can read off the secret integer $\alpha$ by multiplying the last entry by $p$.


### The Extended Hidden Number Problem

The [extended hidden number problem](https://link.springer.com/chapter/10.1007/978-3-540-74462-7_9) extends the HNP to the case in which there are multiple chunks of information known about linear relations of the secret integer. Additionally, it simultaneously deals with the case in which multiple chunks of the secret integer are known. It can be stated as follows.

**(Extended hidden number problem).** Let $p$ be a prime and let $x \in [1, p-1]$ be a secret integer such that

$$
x = \bar{x} + \sum_{j=1}^m 2^{\pi_j} x_j
$$

where the integers $\bar{x}$ and $\pi_j$ are known, and the unknown integers $x_j$ satisfy $0 \leq x_j < 2^{\nu_j}$ for known integers $\nu_j$. Suppose we are given $d$ equations

$$
\alpha_i \sum_{j=1}^m 2^{\pi_j} x_j + \sum_{j=1}^{l_i} \rho_{i,j} k_{i,j} = \beta_i - \alpha_i \bar{x} \pmod p
$$

for $1 \leq i \leq d$ where $\alpha_i \neq 0 \pmod p$, $\rho_{i, j}$ and $\beta_i$ are known integers. The unknown integers $k_{i,j}$ are bounded by $0 \leq k_{i,j} < 2^{\mu_{i,j}}$ where the $\mu_{i,j}$ are known. The extended hidden number problem (EHNP) is to find $x$. The EHNP instance is represented by

$$
\left ( \bar{x}, p, \{ \pi_j, \nu_j \}_{j=1}^m, \left \{ \alpha_i, \{ \rho_{i,j}, \mu_{i,j} \}_{j=1}^{l_i}, \beta_i \right \}_{i=1}^d \right )
$$

As with the hidden number problem, we model the situation as a CVP instance. The main idea behind the lattice basis used to solve the EHNP is similar to that of the regular HNP except the EHNP lattice involves factors to deal with the varying sizes of the unknown chunks. For a $\delta > 0$, we construct the EHNP lattice basis $\mathbf{B}$:

$$
\mathbf{B} =
\begin{bmatrix}
  p \cdot \mathbf{I}_{d} \\
  \mathbf{A} & \mathbf{X} \\
  \mathbf{R} & & \mathbf{K}
\end{bmatrix}
$$

with the following definitions:

$$
\begin{aligned}
  % L &= \sum_{i=1}^d l_i \\
  % D &= d + m + L \\
  \mathbf{A} &=
  \begin{bmatrix}
    \alpha_1 2^{\pi_1} & \alpha_2 2^{\pi_1} & \cdots & \alpha_d 2^{\pi_1} \\
    \alpha_1 2^{\pi_2} & \alpha_2 2^{\pi_2} & \cdots & \alpha_d 2^{\pi_2} \\
    \vdots & \ddots & & \vdots \\
    \alpha_1 2^{\pi_m} & \alpha_2 2^{\pi_m} & \cdots & \alpha_d 2^{\pi_m}
  \end{bmatrix}
  &&\qquad
  \mathbf{X} = \mathrm{diag} \left ( \frac{\delta}{2^{\nu_1}}, \frac{\delta}{2^{\nu_2}}, \ldots, \frac{\delta}{2^{\nu_m}} \right ) \\
  \mathbf{R} &=
  \begin{bmatrix}
    \rho_{1,1} \\ \vdots \\ \rho_{1,l_1} \\
    & \ddots \\
    & & \rho_{d,1} \\ & & \vdots \\ & & \rho_{d,l_d} \\
  \end{bmatrix}
   &&\qquad
   \mathbf{K} = \mathrm{diag} \left ( \frac{\delta}{2^{\mu_{1,1}}}, \ldots, \frac{\delta}{2^{\mu_{1,l_1}}}, \ldots, \frac{\delta}{2^{\mu_{d,1}}}, \ldots, \frac{\delta}{2^{\mu_{d,l_d}}} \right )
\end{aligned}
$$

To understand what vector we should target with CVP, we rewrite the EHNP equations as

$$
\alpha_i \sum_{j=1}^m 2^{\pi_j} x_j + \sum_{j=1}^{l_i} \rho_{i,j} k_{i,j} + r_i p = \beta_i - \alpha_i \bar{x}

$$
for integers $r_i$. Now, consider the lattice vector $\mathbf{u}$ generated by the linear combination $\mathbf{x}$ which contains secret information:

$$
\mathbf{x} = (r_1, \ldots, r_d, x_1, \ldots, x_m, k_{1,1}, \ldots, k_{1,l_1}, \ldots, k_{d,1}, \ldots, k_{d,l_d})
$$

We have

$$
\mathbf{x} \mathbf{B} = \mathbf{u} = \left (\beta_1 - \alpha_1 \bar{x}, \ldots, \beta_d - \alpha_d \bar{x}, \frac{x_1 \delta}{2^{\nu_1}}, \ldots, \frac{x_m \delta}{2^{\nu_m}}, \frac{k_{1,1} \delta}{2^{\mu_{1,1}}}, \ldots, \frac{k_{1,l_1} \delta}{2^{\mu_{1,l_1}}}, \ldots, \frac{k_{d,1} \delta}{2^{\mu_{d,1}}}, \ldots, \frac{k_{d,l_d} \delta}{2^{\mu_{d,l_d}}} \right ) \\
$$

Then, letting

$$
\mathbf{w} = \left (\beta_1 - \alpha_1 \bar{x}, \ldots, \beta_d - \alpha_d \bar{x}, \frac{\delta}{2}, \ldots, \frac{\delta}{2}, \frac{\delta}{2}, \ldots, \frac{\delta}{2}, \ldots, \frac{\delta}{2}, \ldots, \frac{\delta}{2} \right )
$$

we notice that $\mathbf{w}$ is close to the lattice vector $\mathbf{u}$. Therefore, by solving the CVP instance with $\mathbf{w}$ as the target vector, we may reveal the lattice vector $\mathbf{u}$ that encodes the secret chunks $x_j$ in the $(d+1)$st to $(d+m)$th entries.

### Finding the HNP <a name="finding-the-hnp"></a>

We can think to use (E)HNP in settings where we have many linear expressions involving a secret value which are bounded by values which are "small" relative to the modulus. Because the homomorphic property of RSA implies malleability, an RSA decryption oracle is an almost perfect situation for this to happen.

We have the path solution ciphertext $c = m^e \pmod n$ where $m$ is the path solution itself. By querying the oracle with ciphertext values of $r^e c \pmod n$, we may learn some information about $r m \pmod n$. But what information can we learn exactly?

We remember that our goal is to obtain bounded expressions involving $m$. We're quite close already since the oracle is telling us about properties of $r m \pmod n$. In fact, it turns out that we can learn about the size of $r m \pmod n$ using the oracle. The main idea revolves around shifting $r m \pmod n$ to the left two bits at a time and observing the new final position.

Let $r \in [1, n)$ be a random value. We query the oracle with $r^e c \pmod n$ to learn that the final position of the path $r m \pmod n$ is $(x, y)$. Next, we query the oracle with $(4r)^e c \pmod n$. This gives us the position $(x', y')$ of the path $4 r m \pmod n$. This value is of interest because with high probability, when the two MSBs of $r m \pmod n$ are $0$, then the the two LSBs of $4 r m \pmod n$ will also be $0$ (because the shifting didn't cause a modulo reduction). Since there is one additional "L" in the path of $4 r m \pmod n$ in this case, in terms of the final position, we see that this will be identifiable when $x' = x - 1$ and $y = y'$. We can repeat this process with $4^2 r m \pmod n$ and so on to get a tighter upper bound on $rm \pmod n$.

With this, all we need to do is find many $r_i$ such that $r_i m \pmod n$ is bounded. We then get the expressions

$$
\begin{aligned}
    r_i m &< U_i \pmod n \\
    \implies \beta_i - r_i m &= 0 \pmod n
\end{aligned}
$$

where $|\beta_i| < U_i$. This is precisely an (extended) hidden number problem.

### Implementation

```py
from pwn import *
import ast

# https://github.com/josephsurin/lattice-based-cryptanalysis/
from lbc_toolkit import ehnp

directions = "LRUD"
def toPath(x: int):
    s = bin(x)[2:]
    if len(s) % 2 == 1:
        s = "0" + s

    path = ""
    for i in range(0, len(s), 2):
        path += directions[int(s[i:i+2], 2)]
    return path

def query(c):
    conn.sendlineafter(b'Check answer.\n', b'1')
    conn.sendlineafter(b'hex: ', hex(c).encode())
    final_pos = ast.literal_eval(conn.recvline().decode().strip())
    return final_pos

def blinded_query(r, c):
    return query((pow(r, e, n) * c) % n)

def get_flag(sol_int):
    path = toPath(sol_int)
    conn.sendlineafter(b'Check answer.\n', b'2')
    conn.sendlineafter(b'Solution: ', path.encode())
    return conn.recvline().decode()

conn = remote('challs.ctf.sekai.team', 3005)
conn.recvline()
n = int(conn.recvline().decode().strip().split('n = ')[1])
e = int(conn.recvline().decode().strip().split('e = ')[1])
c = int(conn.recvline().decode().strip(), 16)

rs_and_Us = []
while len(rs_and_Us) < 30:
    r = randint(1, n)
    x, y = blinded_query(r, c)
    r_ = r
    cnt = 0
    while True:
        r_ = 4*r_
        x_, y_ = blinded_query(r_, c)
        if x_ != x - 1 or y != y_:
            if cnt >= 4:
                rs_and_Us.append((r, 1024 - 2*cnt))
                print('got!', len(rs_and_Us))
            break
        x = x_
        cnt += 1

xbar = 0
Pi = [0]
Nu = [128]
Alpha = [r for r, _ in rs_and_Us]
ell = len(rs_and_Us)
Rho = [[1]] * ell
Mu = [[U] for _, U in rs_and_Us]
Beta = [0] * ell
sol = ehnp(xbar, n, Pi, Nu, Alpha, Rho, Mu, Beta, delta=1/10^22, verbose=True)
print(sol)

if sol > 2^130:
    sol = -sol % n

print(get_flag(sol))

# SEKAI{parity_reveals_everything_:<_8f1261a517796b4d}
```
