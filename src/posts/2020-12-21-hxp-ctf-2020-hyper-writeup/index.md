---
path: /posts/2020-12-21-hxp-ctf-2020-hyper-writeup
title: hxp CTF 2020 - hyper
date: 2020-12-21
tags: ctf,infosec,writeup,crypto
---

Difficult CTF...

# hyper (hxp CTF 2020)

> Good luck! :-)

```py
#!/usr/bin/env sage
import struct
from random import SystemRandom

p = 10000000000000001119

R.<x> = GF(p)[]; y=x
f = y + prod(map(eval, 'yyyyyyy'))
C = HyperellipticCurve(f, 0)
J = C.jacobian()

class RNG(object):

    def __init__(self):
        self.es = [SystemRandom().randrange(p**3) for _ in range(3)]
        self.Ds = [J(C(x, min(f(x).sqrt(0,1)))) for x in (11,22,33)]
        self.q = []

    def clk(self):
        self.Ds = [e*D for e,D in zip(self.es, self.Ds)]
        return self.Ds

    def __call__(self):
        if not self.q:
            u,v = sum(self.clk())
            rs = [u[i] for i in range(3)] + [v[i] for i in range(3)]
            assert 0 not in rs and 1 not in rs
            self.q = struct.pack('<'+'Q'*len(rs), *rs)
        r, self.q = self.q[0], self.q[1:]
        return r

    def __iter__(self): return self
    def __next__(self): return self()

flag = open('flag.txt').read().strip()
import re; assert re.match(r'hxp\{\w+\}', flag, re.ASCII)

text = f"Hello! The flag is: {flag}"
print(bytes(k^^m for k,m in zip(RNG(), text.encode())).hex())
```

```
a0955c882185b50a69d9d19a24778519d6da23894e667d7130b495b645caac72163d242923caa00af845f25890
```

## Solution

The flag is encrypted by XORing it with outputs of the hyperelliptic curve based RNG. We have some known plaintext, so we can recover some bytes of the RNG output. The task is to use this bit of known output to get the next few outputs.

### Background

A hyperelliptic curve of genus $g$ over a field $K$ is given by the equation

$$
C : y^2 + h(x)y = f(x)
$$

where $h(x), f(x) \in K[x]$, and $\deg(h(x)) \leq g$, and $\deg(f(x)) = 2g + 1$.

There is no way to define an operation that gives $C$ a group structure, but we can use a related object called the Jacobian of $C$, denoted $J(C)$, which can be equipped with a group law. See [here](https://en.wikipedia.org/wiki/Imaginary_hyperelliptic_curve) and [here](https://homes.esat.kuleuven.be/~fvercaut/papers/cc03.pdf) for an introduction to hyperelliptic curves.

Essentially, every element $D \in J(C)$ can be uniquely represented as a pair $\langle u(x), v(x) \rangle$ of polynomials in $K[x]$. This is the Mumford representation of $D$. The polynomials satisfy the properties:

a) $u(x)$ is monic

b) $u(x)$ divides $f(x) - h(x)v(x) - v^2(x)$

c) $\deg(v(x)) < \deg(u(x)) \leq g$

These properties will come in handy soon!

### Analysis

In the challenge, the curve is of genus 3 and has equation

$$
y^2 = x + x^7
$$

(i.e. $h(x) = 0$ and $f(x) = x + x^7$).

The RNG generates three large random numbers $e_1, e_2$ and $e_3$, as well as three constant elements $D_1, D_2, D_3 \in J(C)$. To generate random bytes, the RNG computes

$$
\langle u(x), v(x) \rangle = e_1 D_1 + e_2 D_2 + e_3 D_3
$$

and converts the coefficients of $u(x)$ and $v(x)$ to bytes (excluding the coefficient of $x^3$ in $u(x)$ which is $1$ since $u(x)$ is monic).

Since we have 24 bytes of known plaintext, we can completely recover $u(x)$. To recover the next outputs of the RNG, we'll need to somehow determine $v(x)$.

### Solving the challenge

From the properties of elements in $J(C)$ listed above, we have

$$
f(x) - h(x)v(x) - v^2(x) \equiv 0 \pmod{u(x)}
$$

so if $x_i$ is a root of $u$ (over the algebraic closure of $K$), then

$$
\begin{aligned}
    f(x_i) - h(x_i)v(x_i) - v^2(x_i) &= 0 \\
    \implies v^2(x_i) + h(x_i)v(x_i) &= f(x_i)
\end{aligned}
$$

which implies that $(x_i, v(x_i))$ is a point on $C$.

In the challenge, $h = 0$, so we have

$$
v^2(x_i) = f(x_i) \implies v(x_i) = \pm \sqrt{f(x_i)}
$$

Now, remember that we have $u(x)$, and we want to recover $v(x)$. It turns out we have just enough information to do that! $u(x)$ is of degree $3$, so over the algebraic closure of $K$, we can find three roots $x_1, x_2$ and $x_3$. We just argued that the points $(x_1, v(x_1))$, $(x_2, v(x_2))$ and $(x_3, v(x_3))$ lie on the curve $C$, so we have some candidates of $v(x_1), v(x_2)$ and $v(x_3)$ (namely $\pm \sqrt{f(x_1)}$ and so on). To recover the polynomial $v(x)$, we can use [Lagrange interpolation](https://en.wikipedia.org/wiki/Polynomial_interpolation).

**Solve script:**

```py
import itertools
import struct

p = 10000000000000001119

R.<x> = GF(p)[]; y=x
f = y + prod(map(eval, 'yyyyyyy'))
C = HyperellipticCurve(f, 0)
J = C.jacobian()
Ds = [J(C(x, min(f(x).sqrt(0,1)))) for x in (11,22,33)]

enc = bytes.fromhex('a0955c882185b50a69d9d19a24778519d6da23894e667d7130b495b645caac72163d242923caa00af845f25890')
known_pt = 'Hello! The flag is: hxp{'.encode()

rng_output = bytes(e^^m for e,m in zip(enc, known_pt))

blocks = [rng_output[i:i+8] for i in range(0, len(rng_output), 8)]
ui = [int.from_bytes(r, 'little') for r in blocks]
u = x^3 + ui[2]*x^2 + ui[1]*x + ui[0]

L = GF(p).algebraic_closure()
roots = [r[0] for r in u.change_ring(L).roots()]

RR.<zz> = PolynomialRing(L)
v = RR.lagrange_polynomial([(xi, f(xi).sqrt()) for xi in roots])
vi = [v.coefficients()[i].as_finite_field_element()[1] for i in range(3)]
vi = [(int(-c), int(c)) for c in vi]

for rs in itertools.product(*vi):
    q = struct.pack('<'+'Q'*len(rs), *rs)

    flag = bytes(k^^m for k,m in zip(rng_output+q, enc))
    print(flag)
```

Flag: `hxp{ez_P4rT_i5_ez__tL0Cm}`
