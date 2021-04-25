---
path: /posts/2021-04-25-s4ctf-crypto-writeups
title: S4CTF 2021 - Crypto/Misc
date: 2021-04-25
tags: ctf,infosec,writeup,crypto
---

S4CTF had some nice crypto challenges. I played solo this time and managed to reach #6.

- [Baby-XoR](#babyxor)
- [Baby-IQ](#babyiq)
- [Baby-RSA](#babyrsa)
- [Khayyam](#khayyam)
- [Merles](#merles)
- [Genie](#genie)
- [Phillip](#phillip)
- [Malady](#malady)
- [Determinant](#determinant)
- [PTS](#pts)

# Baby-XoR <a name="babyxor"></a>

> The first technique one should learn, in order to enter the fun world of modern cryptography, is XoR. Have you learned it well? 

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flag import flag

def xor(u, v):    
	return ''.join(chr(ord(cu) ^ ord(cv)) for cu, cv in zip(u, v))

u = flag
v = flag[1:] + flag[0]

enc = open('flag.enc', 'w')
enc.write(xor(u, v))
enc.close()
```

## Solution

For some reason the `flag` variable seems to contain stuff other than the flag, and the flag actually starts from the 13th byte. I figured this out by XORing `S4CTF` with `4CTF{` and seeing where the result occurs in the given ciphertext. We can build up the flag byte by byte since XORing the encryption with the current known flag reveals the next byte of the flag.

```py
from pwn import xor

enc = open('flag.enc', 'rb').read()[13:]

flag = 'S4CTF{'.encode()
for _ in enc:
    f = xor(enc[:len(flag)], flag)
    flag += f[-1:]
    if flag[-1] == 125:
        break
print(flag.decode())
```

Flag: `S4CTF{XOR_x0r_XoR_X0r_xOr!!!}`

# Baby-IQ <a name="babyiq"></a>

> Use this simple crypto algorithm to learn about padding and evaluate yourself on how well you understand algorithms.

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from math import sqrt
from flag import flag
import os
import random
import base64

def chunkchunk(msg, l):
	return [msg[l*i:l*(i + 1)] for i in range(0, len(msg) // l)]

def pad(msg):
	r = int(sqrt(len(msg))) + 1
	head = base64.b64encode(os.urandom(r**2))[:r**2 - (len(msg))]
	msg = head + msg.encode('utf-8')
	msg = chunkchunk(msg, r)
	return [list(m) for m in msg]

def encrypt(A):
	row = len(A)
	col = len(A[0])
	top = 0
	left = 0
	tmp = []
	while (top < row and left < col) :       
		for i in range(left, col) : 
			tmp.append(A[top][i])              
		top += 1
		for i in range(top, row) : 
			tmp.append(A[i][col - 1])     
		col -= 1
		if ( top < row) : 
			for i in range(col - 1, left - 1, -1) : 
				tmp.append(A[row - 1][i])  
			row -= 1
		  
		if (left < col) : 
			for i in range(row - 1, top - 1, -1) : 
				tmp.append(A[i][left])   
			left += 1
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(A[0])):
			r.append(tmp[i*len(A[0]) + j])
		result.append(r)
	return result

A = pad(flag)
for _ in range(len(A)):
	_ = encrypt(A)
	A = _

print('enc =', A)
```

## Solution

Without doing much reversing to find out what `encrypt` is actually doing, we can see from the ciphertext that all that's happening is transposing and shuffling. This gave me the idea to just repeatedly apply `encrypt` on the ciphertext in hopes that the transformation becomes the identity map after enough applications.

```py
def encrypt(A):
    row = len(A)
    col = len(A[0])
    top = 0
    left = 0
    tmp = []
    while (top < row and left < col) :       
        for i in range(left, col) : 
            tmp.append(A[top][i])              
        top += 1
        for i in range(top, row) : 
            tmp.append(A[i][col - 1])     
        col -= 1
        if ( top < row) : 
            for i in range(col - 1, left - 1, -1) : 
                tmp.append(A[row - 1][i])  
            row -= 1
          
        if (left < col) : 
            for i in range(row - 1, top - 1, -1) : 
                tmp.append(A[i][left])   
            left += 1
    result = []
    for i in range(len(A)):
        r = []
        for j in range(len(A[0])):
            r.append(tmp[i*len(A[0]) + j])
        result.append(r)
    return result

enc = [[122, 83, 52, 67, 84, 70], [89, 114, 79, 48, 67, 125], [95, 121, 114, 53, 116, 55], [123, 95, 80, 51, 52, 95], [102, 115, 114, 95, 119, 107], [52, 117, 109, 33, 97, 112]]

for _ in range(32*len(enc)):
    _ = encrypt(enc)
    enc = _
    d = ''.join(''.join(map(chr, r)) for r in enc)
    if 'S4CTF{' in d and d[-1] == '}':
	    print(d[1:])
```

Flag: `S4CTF{34sY_CryPtO_7a5k_f0r_w4rmup!}`

# Baby-RSA <a name="babyrsa"></a>

> A widely used crypto protocol, which may have been implemented weakly. What do you think?

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Util.number import *
from flag import flag

def create_tuple(nbit): # sorry for dirty code that is not performant!
	while True:
		p, q = [getPrime(nbit) for _ in range(2)]
		P = int(str(p) + str(q))
		Q = int(str(q) + str(p))
		if isPrime(P) and isPrime(Q):
			return P, Q

def encrypt(msg, pkey):
	return pow(bytes_to_long(msg), 31337, pkey)

nbit = 256
P, Q = create_tuple(nbit)
pkey = P * Q
enc = encrypt(flag.encode('utf-8'), pkey)

print('pkey =', pkey)
print('enc =', enc)
```

## Solution

A 1024 bit RSA modulus is generated by choosing two random 256 bit primes `p` and `q`, and constructing the 512 bit primes `P = int(str(p) + str(q))` and `Q = int(str(q) + str(p))` (such primes `p` and `q` seem to be quite rare; I wasn't able to get local values to test with before I solved the challenge).

We'll make the assumption that there are 77 digits in both $p$ and $q$ (this is the case in the challenge, but if it weren't, we could just try with different values around 77). Then

$$
\begin{aligned}
    P &= 10^{77} p + q \\
    Q &= 10^{77} q + p
\end{aligned}
$$

So the bivariate polynomial

$$
f(x, y) = N - (10^{77} x + y)(10^{77} y + x)
$$

has "small" roots, which can be easily found using Coppersmith's theorem. As usual, we use [defund's implementation](https://github.com/defund/coppersmith), but it seems to not work over `ZZ` that well, so we construct the polynomial ring over `Zmod(N^2)` (or some other big number such that $N$ doesn't vanish).

```py
from Crypto.Util.number import long_to_bytes
load('small_roots.sage')

N = 48564396752059338791464352725210493148212425902751190745668164451763507023284970474595680869078726765719920168392505794415687815488076204724659643390252172928332322944711949999326843460702414647825442748821062427474599006915155109396213406624079900714394311217571510958430682853948004734434233860146109894977
enc = 28767981118696173499362412795754123415661648348744243377735885542432968964926551295510845917978847771440173910696607195964650864733310997503291576565605508828208679238871651079005335403223194484223700571589836641593207297310906538525042640141507638449129445170765859354237239005410738965923592173867475751585

R.<x,y> = PolynomialRing(Zmod(N^2))
P = 10^77 * x + y
Q = 10^77 * y + x
f = N - P*Q
p, q = small_roots(f, (10^77, 10^77), m=3)[0]

P = int(str(p) + str(q))
Q = int(str(q) + str(p))
d = pow(31337, -1, (P-1)*(Q-1))
m = pow(enc, d, N)
print(long_to_bytes(m).decode())
```

Flag: `S4CTF{Wh3n_mY_BrA1n_w45_UltR4_4CtIVe_ABOut_RSA!!!}`

# Khayyam <a name="khayyam"></a>

> Khayyam was an innovative Iranian mathematician. Let's see if you are up to the challenge with one of his innovations.

```py
#!/usr/bin/env python3

from gmpy import *
from flag import FLAG

l = len(FLAG) // 2

x = int(FLAG[:l].encode("utf-8").hex(), 16)
y = int(FLAG[l:].encode("utf-8").hex(), 16)

p = next_prime(x)
q = next_prime(y)
e, n = 65537, p * q

m_1 = x + int(sqrt(y))
m_2 = y + int(sqrt(x))

c_1, c_2 = pow(m_1, e, n), pow(m_2, e, n)

print('A =', n**2 + c_1)
print('B =', c_2**2 - c_1**2)
print('C =', n**2 + c_2)
```

## Solution

An RSA modulus is generated by choosing two primes $p$ and $q$ which are the closest primes larger than two halves of the flag (which are called $x$ and $y$). Then, the flag is encrypted as

$$
\begin{aligned}
    c_1 &\equiv (x + \sqrt{y})^e \pmod n \\
    c_2 &\equiv (y + \sqrt{x})^e \pmod n
\end{aligned}
$$

We are given the values

$$
\begin{aligned}
    A &= n^2 + c_1 \\
    B &= c_2^2 - c_1^2 \\
    C &= n^2 + c_2
\end{aligned}
$$

The first step is to recover $n$, $c_1$ and $c_2$. This is easy since we have three equations and three unknowns. We can avoid doing the algebra by hand by simply using Sage's inbuilt methods to solve for the unknowns.

Once we have $n$, we'll notice that it's quite small, so it can be easily factored. To recover $x$ and $y$, we use the approximations $\sqrt{p} \approx \sqrt{x}$ and $\sqrt{q} \approx \sqrt{y}$.

```py
from Crypto.Util.number import long_to_bytes

A = 844298886536102102829429887239442280531833016184944310667136996459156918746405824828816678218599392201232600192410066055059804298579937332814877553581599184247404
B = 468537588442373918531086438736512221547939545041235667415870300706375550653375662041142909124331906341047098854068053691093683234579835326888942621717466998635211
C = 844298886536102102829429887239442280531833016184944310667136996459156918746405825386446222977715112808855904143526125215759285866282041700190923770523214222144611

P.<n, c_1, c_2> = PolynomialRing(QQ)
f1 = n^2 + c_1 - A
f2 = c_2^2 - c_1^2 - B
f3 = n^2 + c_2 - C
vals = Ideal([f1, f2, f3]).variety(ring=ZZ)[0]
n, c_1, c_2 = vals[n], vals[c_1], vals[c_2]
print('n:', n)
print('c_1:', c_1)
print('c_2:', c_2)

# factordb (unintended?) but numbers are small
p = 28312905903414733214096354352151962531937
q = 32453658557333630932034374992046016455903
d = inverse_mod(0x10001, (p-1)*(q-1))
m_1 = pow(c_1, d, n)
m_2 = pow(c_2, d, n)

flag1 = long_to_bytes(m_1 - int(sqrt(q)))
flag2 = long_to_bytes(m_2 - int(sqrt(p)))
flag = flag1 + flag2
print('flag:', flag.decode())
```

Flag: `S4CTF{0n3_T45k_8Y__kH4YyAm_M37h0d}`

# Merles <a name="merles"></a>

> Solving an equation with multiple unknowns is very much like finding the secret key and deciphering the secret message.
>
> `nc 157.90.231.113 3776`

## Solution

No source for this challenge, but the service tells us what we need to do:

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+ The mission is simple and vivid, you should report non-zero solution +
+ for the equation 3*x**3 + 4*y**3 + 5*z**3 = 0 (mod p) for give p.    +
+ We mean non-zero solution by this condition: x*y*z != 0 (mod p)      +
+ For example 3*13**3 + 4*15**3 + 5*16**3 = 0 (mod 1399).              +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| Options:
|	[R]eport solution!
|	[P]rint the p
|	[Q]uit
```

We need to solve the equation

$$
3x^3 + 4y^3 + 5z^3 \equiv 0 \pmod p
$$

for a given $p$. The approach is to choose any $x$ and $y$, then solve for $z$:

$$
z^3 \equiv -\frac{3x^3 + 4y^3}{5} \pmod p
$$

with, good enough probability, we will be able to solve for $z$.

```py
import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import *
from parse import parse

conn = remote('157.90.231.113', 3776)
[conn.recvline() for _ in range(10)]

conn.sendline('P')
p = list(parse('| p = {:d}\n', conn.recvline().decode()))[0]

F = GF(p)
x = 1337
y = 1337
z3 = F(3*x^3 + 4*y^3)/F(-5)
z = z3.nth_root(3)
assert F(3*x^3 + 4*y^3 + 5*z^3) == 0

conn.sendline('R')
conn.sendline(str((x, y, z)))
conn.interactive()
```

# Genie <a name="genie"></a>

> A hand made and complex crypto system which looks secure. Do you agree?

```py
#!/usr/bin/env python3

import numpy as np
import random
from flag import FLAG

p = 8443

def vsum(u, v):
	assert len(u) == len(v)
	l, w = len(u), []
	for i in range(l):
		w += [(u[i] + v[i]) % p]
	return w

def sprod(a, u):
	w = []
	for i in range(len(u)):
		w += [a*u[i] % p]
	return w

def encrypt(msg):
	l = len(msg)
	genie = [ord(m)*(i+1) for (m, i) in zip(list(msg), range(l))]
	V, W = [], []
	for i in range(l):
		v = [0]*i + [genie[i]] + [0]*(l - i - 1)
		V.append(v)
	for i in range(l):
		R, v = [random.randint(0, 126) for _ in range(l)], [0]*l
		for j in range(l):
			v = vsum(v, sprod(R[j], V[j]))
		W.append(v)
	return W

enc = encrypt(FLAG)
print(enc)
```

## Solution

The flag is encrypted by taking the ASCII codes of each character $m_1, m_2, \ldots, m_n$ and computing the matrix

$$
W =
R
\begin{bmatrix}
    m_1 \\
    & 2 m_2 \\
    & & \ddots \\
    & & & & n m_n
\end{bmatrix}

\pmod {8443}
$$

where $R$ is a $n \times n$ matrix with random entries in the range $[0, 126]$.

There is a linear algebra approach to solving this, which is the intended solution, but it can be solved (in my opinion) a bit easier by noticing the following.

The $k$th column $W_k$, of $W$, contains entries of the form $r (k m_k)$ where $r$ is a random number in $[0, 126]$. The approach is to bruteforce all possible values $m_k'$ of $m_k$ and all possible values of $r$, and choose the candidate $m_k'$ which satisfies the property that all of the entries in $W_k$ are of the form $r' (k m_k')$ for some $r' \in [0, 126]$. In the challenge, the flag is 67 characters, so each column has 67 entries. This is enough to determine the correct candidate for each character of the flag.

```py
from string import printable

p = 8443
W = eval(open('./enc.txt').read())
columns = list(zip(*W))

flag = ''
for i,col in enumerate(columns):
    pos = []
    for m in printable:
        g = ord(m)*(i+1)
        V = [g*r % p for r in range(127)]
        if len(set(col) - set(V)) == 0:
            flag += m
print(flag)
```

Flag: `S4CTF{91v3n_a_L1n3AR_7r4n5FoRma7iOn_A_4_V3cT0r_x_5UcH_tHA7_Ax=lx!!}`

# Phillip <a name="phillip"></a>

> Goal is to find collisions in this hash algorithm. Perhaps not as easy!
>
> `nc 157.90.231.113 9999`

```py
#!/usr/bin/env python3

from Crypto.Util.number import *
from gmpy2 import next_prime, gcd, lcm
from random import randint
import sys, os, signal
import inspect
from flag import flag

def make_params(nbit):
	p, q = [getPrime(nbit) for _ in range(2)]
	n, f, g = p * q, lcm(p-1, q-1), p + q
	e = pow(g, f, n**2)
	u = divmod(e-1, n)[0]
	v = inverse(u, n)
	params = int(n), int(f), int(v)
	return params

def phillip_hash(m, params):
	n, f, v = params
	if 1 < m < n**2 - 1:
		e = pow(m, f, n**2)
		u = divmod(e-1, n)[0]
		H = divmod(u*v, n)[1]
	return H

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.readline().strip()

def main():
	border = "+"
	pr(border*72)
	pr(border, " hi young cryptographers,! Your mission is to find a hash collision ", border)
	pr(border, " in the given hash function based on famous cryptographic algorithm ", border)
	pr(border, " see the source code and get the flag!                              ", border)
	pr(border*72)

	nbit = 256
	params = make_params(nbit)
	n = params[0]

	while True:
		pr("| Options: \n|\t[H]ash function \n|\t[R]eport collision! \n|\t[T]ry hash \n|\t[G]et params \n|\t[P]arams function \n|\t[Q]uit")
		ans = sc().lower()
		if ans == 'h':
			pr(inspect.getsource(phillip_hash))
		elif ans == 'p':
			pr(inspect.getsource(make_params))
		elif ans == 'r':
			pr("| please send first msg: ")
			m_1 = sc()
			pr("| please send second msg:")
			m_2 = sc()
			try:
				m_1 = int(m_1)
				m_2 = int(m_2)
			except:
				die("| sorry! your input is invalid, Bye!!")
			if m_1 != m_2 and 1 < m_1 < n**2-1 and 1 < m_2 < n**2-1 and phillip_hash(m_1, params) == phillip_hash(m_2, params):
				die("| Congrats! You find the collision!! the flag is:", flag)
			else:
				die("| sorry! your input is invalid or wrong!!")
		elif ans == 't':
			pr("| please send your message to get the hash: ")
			m = sc()
			try:
				m = int(m)
				pr("phillip_hash(m) =", phillip_hash(m, params))
			except:
				die("| sorry! your input is invalid, Bye!!") 
		elif ans == 'g':
			pr('| params =', params)
		elif ans == 'q':
			die("Quiting ...")
		else:
			die("Bye ...")

if __name__ == '__main__':
	main()
```

## Solution

Before getting out pen and paper, I noticed that the hash function is based on RSA, so I decided to check what $n$ and $2n$ hash to. I got lucky as it turns out this is a collision, which solves the challenge. It's easy to see why this works:

The parameters are $(n, f, v)$ where $n = pq$ is an RSA modulus, $f = \lambda(N) = \mathrm{lcm}(p-1, q-1)$ and $v = p + q$. To hash a message $1 < m < n^2 - 1$, the values

$$
\begin{aligned}
    e &\equiv m^f \pmod {n^2} \\
    u &= \left \lfloor \frac{e-1}{n} \right \rfloor \\
\end{aligned}
$$

are computed. The hash is then computed as $H = uv \pmod n$.

Since $H$ is dependent on $u$, and $u$ is dependent on $e$ which in turn is dependent on the message $m$, all we need to do to create a collision is find $m$ and $m'$ such that $e = m^f \pmod {n^2}$ and $e' \equiv (m')^f \pmod {n^2}$ are equal. Since $e$ is reduced modulo $n^2$, it's easy to see that $(kn)^f \pmod {n^2} \equiv 0$ for all $k$ (since $f \geq 2$). So any two multiples of $n$ gives a collision.

Flag: `S4CTF{A94In__pr0b4b1liStiC__aSymM37r1c_Al9OriThm!!}`

# Malady <a name="malady"></a>

> Using finite fields incorrectly in modern cryptography could be dangerous. Try your luck in deciphering this crypto system.

```py
#!/usr/bin/env sage

from flag import flag

def make_matrix(n):
	Zn = IntegerModRing(n)
	G = GL(2, Zn)
	while True:
		a, b, c, d = [randint(0, n - 1) for _ in range(4)]
		P = G([[a, b], [c, d]])
		if P in G:
			return P

def bpow(P, n):
	if n == 0:
		return P
	for _ in range(n):
		P = P ** 2
	return P

def make_keypair(n):
	Zn = IntegerModRing(n)
	G = GL(2, Zn)
	I = G([[1, 0], [0, 1]])
	r = randint(1, 2 ** 256)
	br = bin(r)[2:][::-1]
	J = I
	while True:
		P, Q = [make_matrix(n) for _ in range(2)]
		try:	
			if Q * (~P) != P * Q:
				for i in range(len(br)):
					if br[i] == '1':
						J = bpow(Q, i) * J
				B = (~Q) * (~P) * Q
				pubkey = (n, P, B, J)
				privkey = Q
				return (pubkey, privkey)
		except:
			continue

def encrypt(m, pubkey):
	n, P, B, J = pubkey
	Zn = IntegerModRing(n)
	G = GL(2, Zn)
	I = G([[1, 0], [0, 1]])
	s = randint(1, 2 ** 32)
	bs = bin(s)[2:][::-1]
	D = I
	for i in range(len(bs)):
		if bs[i] == '1':
			D = bpow(J, i) * D
	E = (~D) * P * D
	K = (~D) * B * D
	l = len(str(m))
	M = []
	for i in range(0, 4):
		M.append(int(str(m)[i*l // 4: (i+1)*l // 4]))
	U = matrix([[M[1], M[0]], [M[3], M[2]]])
	V = K * U * K
	return (V, E)

p = next_prime(randint(1, 2 ** 72))
q = next_prime(randint(1, 2 ** 72))

n = p * q
pubkey, privkey = make_keypair(n)

flag = flag.encode('utf-8')
m = int(flag.hex(), 16)
enc = encrypt(m, pubkey)

print('pubkey = ', pubkey)
print('enc = ', enc)
```

## Solution

After a bit of searching, I found the name of the cryptosystem. It's the [Cayley-Purser algorithm](https://en.wikipedia.org/wiki/Cayley%E2%80%93Purser_algorithm) and an attack is described in the wikipedia page.

The key is generated by choosing two random matrices $P, Q \in \mathrm{GL}(2, n)$ such that $QP^{-1} \neq PQ$. Then $B = Q^{-1} P^{-1} Q$ and $J = Q^r$ are computed (for some random, large $r$). The public key is $(n, P, B, J)$ and the private key is $Q$.

To encrypt a message encoded as a $2 \times 2$ matrix $M$, a random value $s$ is generated and the matrices

$$
\begin{aligned}
    D &= J^s \\
    E &= D^{-1} P D \\
    K &= D^{-1} B D \\
    V &= K M K
\end{aligned}
$$

are computed. The ciphertext outputted is the pair $(V, E)$.

To decrypt $(V, E)$ with the private key $Q$, the decryption matrix is computed as $K' = Q^{-1} E Q$. Then the plaintext message is recovered by computing $M = K' V K'$.

The attack begins by solving for $d$ in the congruence

$$
d (B - P^{-1}) \equiv P^{-1} J - JB \pmod n
$$

Then, $Q' = dI + J$ is a multiple of $Q$. A multiple of $Q$ can be used as a valid private key since $K' =(kQ)^{-1} E kQ = k^{-1} Q^{-1} E k Q = Q^{-1} E Q$.

The challenge should be easy from here on, but I kept getting garbage when trying to decrypt. The issue is in the way the message is encoded as a matrix:

```py
l = len(str(m))
M = []
for i in range(0, 4):
    M.append(int(str(m)[i*l // 4: (i+1)*l // 4]))
U = matrix([[M[1], M[0]], [M[3], M[2]]])
```

The flag is represented as a decimal integer, and each entry of the matrix is created by taking equal chunks of the flag as a string. Even if we recover the plaintext message as above, combining the entries into a single string might not work, because leading zeros are truncated after the call to `int`. To fix this, we have to account for the fact that some of the entries in the plaintext message might have a zero in front of them. It turned out that `M[1]` had a zero in front of it.

```py
from Crypto.Util.number import long_to_bytes

n = 2419329577094580148790320061829248654877619
P = [[1181968185527581745853359689584528732855897, 153406550412853584463306785000418170296859],
     [1454322498540966456231711148502103233345812, 1654517770461057329449871572441944497585269]]
B = [[1268457653971486225679848441105472837265167, 579420771722577779695828127264001257349949],
     [2351869917091027496266981633084389584522183, 450983777743266243622871312465133743097962]]
J = [[2358538357277340167153980348659698938509404, 365220208942190647616618122919911425848374],
     [47691648572918059476944115452005044039782, 1236869052280934587487352533961953209955284]]
V = [[425149944883810928331948322693601721947824, 1442606353540488031613587882680057605691721],
     [2270690430439772938430962982653361813264189, 1607654191517170510458852398046623728536109]]
E = [[177396832593088516072893113015799710489963, 2001682469448750676325856357286302774486863],
     [5338037289866014093970785328310590783999, 239759546300970410440018087181424865073584]]

Zn = Zmod(n)
P, B, J, V, E = [Matrix(Zn, X) for X in [P, B, J, V, E]]

L = B - (~P)
R = (~P)*J  - J*B
d = Zn(R[0][0])/Zn(L[0][0])
assert d*L == R
Q_ = d*Matrix.identity(Zn, 2) + J

K_ = (~Q_)*E*Q_
U = K_*V*K_
M0, M1, M2, M3 = 10*int(U[0][1]), int(U[0][0]), int(U[1][1]), int(U[1][0])
m = int(''.join(map(str, [M0, M1, M2, M3])))
flag = long_to_bytes(m)
print(flag.decode())
```

Flag: `S4CTF{Flannery_f0rmAliz3D__Cayley-Pursers__ruN71mE!}`

# Determinant <a name="determinant"></a>

> Try to calculate matrix determinant!
>
> mirror 1: nc 157.90.231.113 2570
>
> mirror 2: nc 198.211.127.76 2570

## Solution

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+  hi power programmers and coders! Your mission is to find a unknown  +
+  variables in each step such that the determinant of matrix A is     +
+  equal to 1, for example if A = ([3, 7], [2, x]), then for x = 5 we  +
+  have det(A) = 1, now try to find the flag!                          +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| We know that A = [[9, 'x'], [2, 3]]
| Send unknown variables in matrix A, separated by comma, such that all of them are greater than 1
```

No source, but the task is simple. Given a 2x2 matrix which may contain between one to three unknowns, we need to solve for the unknowns such that the determinant of the matrix is `1`. Additionally, the variables must be greater than a given lower bound. There are quite a few cases to go through, but for each number of unknowns, one case is quite similar to the rest, so I'll go through just a few.

Let

$$
M =
\begin{bmatrix}
    a & b \\
    c & d
\end{bmatrix}
$$

The determinant of $M$ is given by $ad - bc$.

We will consider the cases when $a$ is a variable, when both $a$ and $b$ are variables, when both $a$ and $c$ are variables, and when all of $a, b$ and $c$ are variables. For each case, let $L$ denote the lower bound.

### Case 1: One variable

Suppose we are given the matrix

$$
M = 
\begin{bmatrix}
    x & b \\
    c & d
\end{bmatrix}
$$

So $|M| = xd - bc = 1$. Rearranging, we get $x = \frac{1 + bc}{d}$.

### Case 2a: Two variables

Suppose we are given the matrix

$$
M = 
\begin{bmatrix}
    x & y \\
    c & d
\end{bmatrix}
$$

So $|M| = xd - cy = 1$. We notice that this looks similar to Bezout's identity. It is always the case that $\gcd(d, -c) = 1$, so we can solve this by computing the Bezout coefficients for $(d, -c)$. This can be done with the extended Euclidean algorithm. Suppose we have solutions $x', y'$ such that $x'd - cy' = 1$. All that remains is to ensure $x', y' > L$. Notice that

$$
(x' + kc)d - c(y' + kd) = x'd + kcd - cy' - ckd = x'd - cy' = 1
$$

so it turns out that $(x' + kc)$ and $(y' + kd)$ are also solutions, for any $k$. Choose a large enough $k$ such that our solutions are greater than the lower bound, and we are done.

### Case 2b: Two variables

Suppose we are given the matrix

$$
M = 
\begin{bmatrix}
    x & b \\
    c & y
\end{bmatrix}
$$

So $|M| = xy - bc = 1$. Then $xy = 1 + bc$. So we must choose $x$ and $y$ such that their product is $1 + bc$. We can find candidates for $x$ and $y$ by iterating over the divisors of $1 + bc$, then taking the first pair of divisors such that they are both greater than the lower bound. Since the values are fairly small, factoring $1 + bc$ and computing the divisors can be done in a reasonable time.

### Case 3: Three variables

Suppose we are given the matrix

$$
M = 
\begin{bmatrix}
    x & y \\
    z & d
\end{bmatrix}
$$

So $|M| = xd - zy = 1$. We will reduce this to case (2a) by choosing $y = p$ where $p$ is a prime larger than the lower bound. Then we have the matrix

$$
\begin{bmatrix}
    x & p \\
    z & d
\end{bmatrix}
$$

which is exactly the setting as in case (2a), since $p$ and $d$ are almost guaranteed to be coprime.

```py
from pwn import *
from gmpy2 import gcdext
from primefac import primefac
from functools import reduce
from collections import Counter
from itertools import product
from operator import mul
prod = lambda l: reduce(mul, l, 1)

# https://alexwlchan.net/2019/07/finding-divisors-with-python/
def get_divisors(pf):
    pf_with_multiplicity = Counter(pf)
    powers = [
        [factor ** i for i in range(count + 1)]
        for factor, count in pf_with_multiplicity.items()
    ]
    for prime_power_combo in product(*powers):
        yield prod(prime_power_combo)

p = 104010985514257800469608790443965305580101693802288262284052742898073797789021

def solv_bezouts(a, b, lb):
    _, x, y = gcdext(a, -b)
    d_ = lb*b + x
    c_ = lb*a + y
    return c_, d_

def solve_2(a, b, c, d, lb):
    if type(a) == int and type(b) == int:
        c_, d_ = solv_bezouts(a, b, lb)
        return f'{c_},{d_}'

    elif type(a) == int and type(c) == int:
        b_, d_ = solv_bezouts(a, c, lb)
        return f'{b_},{d_}'

    elif type(a) == int and type(d) == int:
        N = a*d - 1
        F = list(primefac(a*d - 1))
        divs = get_divisors(F)
        for b_ in divs:
            c_ = N//b_
            if b_ > lb and c_ > lb:
                return f'{b_},{c_}'

    elif type(b) == int and type(c) == int:
        N = 1 + b*c
        F = list(primefac(1 + b*c))
        divs = get_divisors(F)
        for a_ in divs:
            d_ = N//a_
            if a_ > lb and d_ > lb:
                return f'{a_},{d_}'

    elif type(b) == int and type(d) == int:
        c_, a_ = solv_bezouts(d, b, lb)
        return f'{a_},{c_}'

    elif type(c) == int and type(d) == int:
        b_, a_ = solv_bezouts(d, c, lb)
        return f'{a_},{b_}'

def do_round():
    known = eval(conn.recvline().decode().strip().split('= ')[1])
    lb = int(conn.recvline().decode().strip().split()[-1])

    print('A:')
    print('\n'.join(' '.join(map(str, r)) for r in known))
    print('lb:', lb)

    (a, b), (c, d) = known

    if sum(int(type(x) == str) for x in [a,b,c,d]) == 3:
        if type(a) == int:
            b_ = p
            c_, d_ = solv_bezouts(a, b_, lb)
            ans = f'{b_},{c_},{d_}'
        elif type(b) == int:
            a_ = p
            c_, d_ = solv_bezouts(a_, b, lb)
            ans = f'{a_},{c_},{d_}'
        elif type(c) == int:
            a_ = p
            b_, d_ = solv_bezouts(a_, c, lb)
            ans = f'{a_},{b_},{d_}'
        elif type(d) == int:
            b_ = p
            c_, a_ = solv_bezouts(d, b_, lb)
            ans = f'{a_},{b_},{c_}'

    elif sum(int(type(x) == str) for x in [a,b,c,d]) == 2:
        ans = solve_2(a, b, c, d, lb)

    elif type(a) == str:
        a_ = (1 + b*c)//d
        ans = str(a_)
    elif type(b) == str:
        b_ = (a*d - 1)//c
        ans = str(b_)
    elif type(c) == str:
        c_ = (a*d - 1)//b
        ans = str(c_)
    elif type(d) == str:
        d_ = (1 + b*c)//a
        ans = str(d_)

    conn.sendline(ans)
    print(conn.recvline().decode())

conn = remote('157.90.231.113', 2570)
[conn.recvline() for _ in range(6)]
while 1:
    do_round()
```

Flag: `S4CTF{5imPl3_PPC_Us1Ng___MatrIx___}`

# PTS <a name="pts"></a>

> Joy of a tour on Graph Matrices, lost in the forest
>
> `nc 198.211.127.76 3580`

## Solution

Similar style challenge to Determinant, we are given a task and have to submit a solution:

```
------------------------------------------------------------------------
|             -+-+ Joy of a tour on Graph Matrices +-+-                |
|      Count number of subtrees of the given matrix M, such that       |
|     M is adjacency matrix of G, a connected graph without loops,     |
|                and this subtree covers all vertices's                |
------------------------------------------------------------------------
| M =
[0, 1, 1, 1]
[1, 0, 1, 1]
[1, 1, 0, 0]
[1, 1, 0, 0]
| please send number of subtrees
```

Just use Sage's `graph.spanning_trees_count()`.

```py
import os
os.environ['PWNLIB_NOTERM'] = 'True'
from collections import defaultdict
from pwn import *

# https://www.geeksforgeeks.org/convert-adjacency-matrix-to-adjacency-list-representation-of-graph/
def adjM_to_list(a):
    adjList = defaultdict(list)
    for i in range(len(a)):
        for j in range(len(a[i])):
            if a[i][j]== 1:
                adjList[i].append(j)
    return adjList

def do_round():
    conn.recvline()
    M = []
    while 1:
        r = conn.recvline().decode()
        if r[0] == '|':
            break
        M.append(eval(r))
    adj_list = adjM_to_list(M)
    D = DiGraph(adj_list)
    n = D.spanning_trees_count()
    conn.sendline(str(n))
    print(conn.recvline().decode())
    
conn = remote('198.211.127.76', 3580)
[conn.recvline() for _ in range(6)]
while 1:
    do_round()
```

Flag: `S4CTF{y3s_0lD__8u7__G0lD_s7ufF_0N__G_M4Tr1c3S}`
