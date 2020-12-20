---
path: /posts/2020-05-13-sharkyctf-2020-writeups
title: SharkyCTF 2020 Writeups
date: 2020-05-13
tags: ctf,infosec,writeup,crypto
---

I played SharkyCTF this weekend on team `misc` and we came 5th.

- crypto
    - [Noisy RSA](#noisy-rsa)


---

# Noisy RSA <a name="noisy-rsa"></a>

### crypto (398pts)

> Something about this randomly generated noise doesn't seem right...

`generate.py`:

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from fractions import gcd
from secret import flag
from Crypto.Random import get_random_bytes

def encrypt(number):
	return pow(number,e,N)

def noisy_encrypt(a,m):
	return encrypt(pow(a,3,N)+(m << 24))

e = 3
p = getStrongPrime(512)
q = getStrongPrime(512)

while (gcd(e,(p-1)*(q-1)) != 1):
	p = getStrongPrime(512)
	q = getStrongPrime(512)

N = p * q

print("N : " + str(N) + "\n")
print("e : " + str(e) + "\n")

rand = bytes_to_long(get_random_bytes(64))

ct = []
ct.append(encrypt(rand << 24))

for car in flag:
	ct.append(noisy_encrypt(car,rand))

print(ct)
```

## Solution

We have a bunch of ciphertexts which are the encryptions of single plaintext characters. The encryption uses low public exponent RSA with linear padding, and we are given the encryption of the padding used as well as some known plaintext/ciphertext pairs (from the flag format). We can use the Franklin-Reiter related message attack to recover the random padding and therefore generate a mapping from possible plaintext characters to their encryption.

### Recovering $r$

Let $r$ denote the random padding used (the `rand` variable in the handout code) and let $M_2 = r \times 2^{24}$. Let $b$ denote the first plaintext character in its integer representation (we know $b = \mathrm{ord}("s") = 115$). Let $C_2$ denote the encryption of $M_2$, that is $C_2 \equiv M_2^e \pmod N$.

Define the function $f(x) = x + b$ and let $M_1 = f(M_2)$. Let $C_1$ denote the encryption of $M_1$, that is $C_1 \equiv f(M_2)^e \pmod N$. It is clear that we have the values of $C_1$ and $C_2$ as they are the second and first values in the `ct` array respectively. Hence, we can define the new functions:

$$
\begin{aligned} g_1 &\equiv f(x)^e - C_1 \pmod N \\ g_2 &\equiv x^e - C_2 \pmod N \end{aligned}
$$

We see that $g_1$ and $g_2$ share a root. Namely, $x = M_2$. Thus, $g_1$ and $g_2$ share the common factor $(x - M_2)$. We can use the Euclidean algorithm to efficiently compute the gcd of the two polynomials and therefore recover the padding.

### Solving the challenge

Now that we have $r$, we can generate a mapping from plaintext characters to their ciphertexts and use this to map the ciphertexts in `ct` to their plaintext.

```python
from string import printable
from values import ct, N, e

C1 = ct[1]
C2 = ct[0]

b = pow(ord('s'), e, N)

Z = Zmod(N)
P.<x> = PolynomialRing(Z)
def pgcd(g1,g2):
    return g1.monic() if not g2 else pgcd(g2, g1%g2)
g1 = (x + b)^e - C1
g2 = x^e - C2
M2 = -pgcd(g1, g2).coefficients()[0]

r = M2 >> 24
# yes we could just use M2 instead of computing r << 24, but this is easier to understand
mapping = { pow(pow(ord(c), 3, N) + (r << 24), e, N):c for c in printable }
flag = ''
for c in ct[1:]:
    flag += mapping[c]
print(flag)
```

Flag: `shkCTF{L0NG_LIV3_N0ISY_RS4_b86040a760e25740477a498855be3c33}`
