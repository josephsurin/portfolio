---
path: /posts/2022-08-08-corctf-2022-crypto-writeups
title: corCTF 2022 - Crypto
date: 2022-08-08
tags: ctf,infosec,writeup,crypto
---


|Challenge|Tags|Solves|
|---|---|---|
|[tadpole](#tadpole)|`lcg`|262|
|[luckyguess](#luckyguess)|`lcg`|150|
|[exchanged](#exchanged)|`lcg` `discrete log`|94|
|[hidE](#hidE)|`rsa` `common modulus attack`|88|
|[generous](#generous)|`okamoto-uchiyama` `lsb oracle`|49|
|[leapfrog](#leapfrog)|`lcg`|36|
|[threetreasures](#threetreasures)|`rsa` `ecc` `coppersmith`|19|
|[corrupted-curves](#corrupted-curves)|`ecc` `LLL`|20|
|[rlfsr](#rlfsr)|`lfsr`|14|
|[corrupted-curves+](#corrupted-curves)|`ecc` `LLL`|15|

# tadpole <a name="tadpole"></a>

> tadpoles only know the alphabet up to b... how will they ever know what p is?

`tadpole.py`:

```py
from Crypto.Util.number import bytes_to_long, isPrime
from secrets import randbelow

p = bytes_to_long(open("flag.txt", "rb").read())
assert isPrime(p)

a = randbelow(p)
b = randbelow(p)

def f(s):
    return (a * s + b) % p

print("a = ", a)
print("b = ", b)
print("f(31337) = ", f(31337))
print("f(f(31337)) = ", f(f(31337)))
```

## Solution

The flag in this challenge happens to be prime and is used as the modulus for an LCG. We are given the multiplier $a$ and the increment $b$ of the LCG, as well as two outputs for a known seed. The goal is to recover the modulus $p$. Let $s = 31337$ and let $z_1, z_2$ be the two outputs we are given. We have the following equations:

$$
\begin{aligned}
    z_1 &= (as + b) \pmod p \\
    z_2 &= a(as + b) + b \pmod p \\
\end{aligned}
$$

which we can rewrite over the integers (for some $k_1, k_2 \in \mathbb{Z}$):

$$
\begin{aligned}
    z_1 &= (as + b) + k_1 p \\
    z_2 &= a(as + b) + b + k_2 p \\
\end{aligned}
$$

Rearranging, we get

$$
\begin{aligned}
    z_1 - (as + b) = k_1 p \\
    z_2 - (a(as + b) + b) = k_2 p \\
\end{aligned}
$$

and so $\gcd(z_1 - (as + b), z_2 - (a(as + b) + b))$ reveals $p$.

```py
from Crypto.Util.number import long_to_bytes

a = 7904681699700731398014734140051852539595806699214201704996640156917030632322659247608208994194840235514587046537148300460058962186080655943804500265088604049870276334033409850015651340974377752209566343260236095126079946537115705967909011471361527517536608234561184232228641232031445095605905800675590040729
b = 16276123569406561065481657801212560821090379741833362117064628294630146690975007397274564762071994252430611109538448562330994891595998956302505598671868738461167036849263008183930906881997588494441620076078667417828837239330797541019054284027314592321358909551790371565447129285494856611848340083448507929914
z1 = 52926479498929750044944450970022719277159248911867759992013481774911823190312079157541825423250020665153531167070545276398175787563829542933394906173782217836783565154742242903537987641141610732290449825336292689379131350316072955262065808081711030055841841406454441280215520187695501682433223390854051207100
z2 = 65547980822717919074991147621216627925232640728803041128894527143789172030203362875900831296779973655308791371486165705460914922484808659375299900737148358509883361622225046840011907835671004704947767016613458301891561318029714351016012481309583866288472491239769813776978841785764693181622804797533665463949
s = 31337

f1 = z1 - (a * s + b)
f2 = z2 - (a * (a * s + b) + b)
p = gcd(f1, f2)
print(long_to_bytes(int(p)).decode())

# corctf{1n_m4th3m4t1c5,_th3_3ucl1d14n_4lg0r1thm_1s_4n_3ff1c13nt_m3th0d_f0r_c0mput1ng_th3_GCD_0f_tw0_1nt3g3rs}
```

# luckyguess <a name="luckyguess"></a>

> i hope you're feeling lucky today
>
> `nc be.ax 31800`

`luckyguess.py`:

```py
#!/usr/local/bin/python
from random import getrandbits

p = 2**521 - 1
a = getrandbits(521)
b = getrandbits(521)
print("a =", a)
print("b =", b)

try:
    x = int(input("enter your starting point: "))
    y = int(input("alright, what's your guess? "))
except:
    print("?")
    exit(-1)

r = getrandbits(20)
for _ in range(r):
    x = (x * a + b) % p

if x == y:
    print("wow, you are truly psychic! here, have a flag:", open("flag.txt").read())
else:
    print("sorry, you are not a true psychic... better luck next time")
```

## Solution

In this challenge, $p = 2^{521} - 1$ is a fixed prime and $a$ and $b$ are randomly generated LCG parameters. To get the flag, we need to provide $x$ and $y$ such that applying the LCG to $x$ a random number of times gives $y$. It is straightforward to find such an $x$ and $y$ by writing the repeated LCG application in a closed form. Define $f(x) = ax + b \pmod p$, then

$$
\begin{aligned}
    f^i(x) &= a^i x + b (a^{i-1} + a^{i-2} + \cdots + 1) \pmod p \\
           &= a^i x + b \frac{a^i - 1}{a - 1} \pmod p
\end{aligned}
$$

Now, we want to find $(x, y)$ such that for a random (or any) $r$, we have $f^r(x) = y$.

$$
\begin{aligned}
    f^r(x) &= y \\
    \implies a^r x + b \frac{a^r - 1}{a - 1} &= y \pmod p \\
    \implies (a-1)a^r x + b(a^r-1) &= (a-1)y \pmod p \\
    \implies  (a-1)a^r x + ba^r - b &= (a-1)y \pmod p
\end{aligned}
$$

Since we don't know $r$, we want to try and get rid of $a^r$ in this expression. A good candidate for $x$ might be $x = -b/(a-1)$. This gives

$$
\begin{aligned}
    (a-1)a^r \frac{-b}{a-1} + ba^r - b &= (a-1)y \pmod p \\
    \implies -b &= (a-1)y \pmod p \\
    \implies y &= \frac{-b}{a-1} \pmod p
\end{aligned}
$$

So $(x, y) = (\frac{-b}{a-1}, \frac{-b}{a-1})$ will work.

```py
from pwn import *

conn = remote('be.ax', 31800)

p = 2**521 - 1
a = int(conn.recvline().decode().strip().split('a = ')[1])
b = int(conn.recvline().decode().strip().split('b = ')[1])
x = y = -b * pow(a - 1, -1, p) % p
conn.sendlineafter(b'starting point: ', str(x).encode())
conn.sendlineafter(b'guess? ', str(y).encode())

print(conn.recvline().decode())

# corctf{r34l_psych1c5_d0nt_n33d_f1x3d_p01nt5_t0_tr1ck_th15_lcg!}
```

# exchanged <a name="exchanged"></a>

> you could make an exchange out of this

`exchanged.py`:

```py
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from secrets import randbelow

p = 142031099029600410074857132245225995042133907174773113428619183542435280521982827908693709967174895346639746117298434598064909317599742674575275028013832939859778024440938714958561951083471842387497181706195805000375824824688304388119038321175358608957437054475286727321806430701729130544065757189542110211847
a = randbelow(p)
b = randbelow(p)
s = randbelow(p)

print("p =", p)
print("a =", a)
print("b =", b)
print("s =", s)

a_priv = randbelow(p)
b_priv = randbelow(p)

def f(s):
    return (a * s + b) % p

def mult(s, n):
    for _ in range(n):
        s = f(s)
    return s

A = mult(s, a_priv)
B = mult(s, b_priv)

print("A =", A)
print("B =", B)

shared = mult(A, b_priv)
assert mult(B, a_priv) == shared

flag = open("flag.txt", "rb").read()
key = sha256(long_to_bytes(shared)).digest()[:16]
iv = long_to_bytes(randint(0, 2**128))
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
print(iv.hex() + cipher.encrypt(pad(flag, 16)).hex())
```

## Solution

This challenge implements a Diffie-Hellman-like key exchange based on the LCG relation $f(s) = as + b \pmod p$. We are given a fixed prime $p$ as well as randomly generated $a, b, s \in [0, p)$. Alice and Bob's private keys are randomly generated $n_a, n_b \in [0, p)$ and we are given $A = f^{n_a}(s)$ and $B = f^{n_b}(s)$. As in the previous LCG challenge, it helps to write out what we have in terms of closed form expressions:

$$
\begin{aligned}
    A &= f^{n_a}(s) \\
      &= a^{n_a}s + b\frac{a^{n_a} - 1}{a - 1} \pmod p \\
\implies A \cdot (a-1) &= a^{n_a} \cdot s(a-1) + b \cdot (a^{n_a} - 1) \pmod p \\
\implies A \cdot (a-1) &= a^{n_a} (as - s + b) - b \pmod p \\
\implies \frac{A \cdot (a-1) + b}{as - s + b} &= a^{n_a} \pmod p \\
\end{aligned}
$$

We know everything in this equation except for $n_a$, so to recover $n_a$ we need to solve a discrete logarithm problem in $(\mathbb{Z}/p\mathbb{Z})^\times$. It turns out that $p-1$ is smooth, so we can solve the DLP easily and recover $n_a$.

Once we have $n_a$, we can compute $f^{n_a}(B)$ to get the shared secret and decrypt the flag.

```py
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

p = 142031099029600410074857132245225995042133907174773113428619183542435280521982827908693709967174895346639746117298434598064909317599742674575275028013832939859778024440938714958561951083471842387497181706195805000375824824688304388119038321175358608957437054475286727321806430701729130544065757189542110211847
a = 118090659823726532118457015460393501353551257181901234830868805299366725758012165845638977878322282762929021570278435511082796994178870962500440332899721398426189888618654464380851733007647761349698218193871563040337609238025971961729401986114391957513108804134147523112841191971447906617102015540889276702905
b = 57950149871006152434673020146375196555892205626959676251724410016184935825712508121123309360222777559827093965468965268147720027647842492655071706063669328135127202250040935414836416360350924218462798003878266563205893267635176851677889275076622582116735064397099811275094311855310291134721254402338711815917
s = 35701581351111604654913348867007078339402691770410368133625030427202791057766853103510974089592411344065769957370802617378495161837442670157827768677411871042401500071366317439681461271483880858007469502453361706001973441902698612564888892738986839322028935932565866492285930239231621460094395437739108335763
A = 27055699502555282613679205402426727304359886337822675232856463708560598772666004663660052528328692282077165590259495090388216629240053397041429587052611133163886938471164829537589711598253115270161090086180001501227164925199272064309777701514693535680247097233110602308486009083412543129797852747444605837628
B = 132178320037112737009726468367471898242195923568158234871773607005424001152694338993978703689030147215843125095282272730052868843423659165019475476788785426513627877574198334376818205173785102362137159225281640301442638067549414775820844039938433118586793458501467811405967773962568614238426424346683176754273
ct = bytes.fromhex('e0364f9f55fc27fc46f3ab1dc9db48fa482eae28750eaba12f4f76091b099b01fdb64212f66caa6f366934c3b9929bad37997b3f9d071ce3c74d3e36acb26d6efc9caa2508ed023828583a236400d64e')

F = GF(p)
ax = F(b + (a - 1) * A) / F(a * s - s + b)
x = discrete_log(F(ax), F(a))

shared = F(a)^x * B + b * F(F(a)^x - 1) / F(a - 1)

key = sha256(long_to_bytes(int(shared))).digest()[:16]
iv = ct[:16]
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
flag = unpad(cipher.decrypt(ct[16:]), 16)
print(flag.decode())

# corctf{th1s_lcg_3xch4ng3_1s_4_l1ttl3_1ns3cur3_f0r_n0w}
```

# hidE <a name="hidE"></a>

> This RSA encryption service is so secure we're not even going to tell you how we encrypted it
>
>  `nc be.ax 31124`

`main.py`:

```py
#!/usr/local/bin/python
import random
import time
import math
import binascii
from Crypto.Util.number import *

p, q = getPrime(512), getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)

flag = open('./flag.txt').read().encode()

random.seed(int(time.time()))

def encrypt(msg):
    e = random.randint(1, n)
    while math.gcd(e, phi) != 1:
        e = random.randint(1, n)
    pt = bytes_to_long(msg)
    ct = pow(pt, e, n)
    return binascii.hexlify(long_to_bytes(ct)).decode()


def main():
    print('Secure Encryption Service')
    print('Your modulus is:', n)
    while True:
        print('Options')
        print('-------')
        print('(1) Encrypt flag')
        print('(2) Encrypt message')
        print('(3) Quit')
        x = input('Choose an option: ')
        if x not in '123':
            print('Unrecognized option.')
            exit()
        elif x == '1':
            print('Here is your encrypted flag:', encrypt(flag))
        elif x == '2':
            msg = input('Enter your message in hex: ')
            print('Here is your encrypted message:', encrypt(binascii.unhexlify(msg)))
        elif x == '3':
            print('Bye')
            exit()

if __name__ == '__main__':
    main()
```

## Solution

In this challenge we have access to an RSA encryption oracle. The interesting part is that the public exponent $e$ is randomly generated for each encryption, and the randomness is seeded by time, so we may be able to recover the generated $e$ for each encryption. When generating the $e$, there is a loop which will repeatedly generate a new $e$ until $\gcd(e, \varphi(n)) = 1$ is satisfied. We do not know $\varphi(n)$, but we can approximate this condition with $\gcd(e, 6) = 1$. 

There is a well known attack against RSA when two coprime public exponents are used to encrypt a message under the same modulus. Suppose $n$ is an RSA modulus and $e_1, e_2$ are coprime. If we are given two encryptions of the message $m$ with $e_1$ and $e_2$ as the public exponents, then we may recover $m$. Specifically, suppose we are given $c_1 = m^{e_1} \pmod n$ and $c_2 = m^{e_2} \pmod n$. Since $e_1$ and $e_2$ are coprime, then we can compute (using the extended Euclidean algorithm) $k_1$ and $k_2$ such that $k_1 e_1 + k_2 e_2 = 1$. Then, computing

$$
\begin{aligned}
    c_1^{k_1} \cdot c_2^{k_2} &= (m^{e_1})^{k_1} (m^{e_2})^{k_2} \pmod n \\
                              &= m^{k_1 e_1 + k_2 e_2} \pmod n \\
                              &= m \pmod n
\end{aligned}
$$

reveals the message $m$.

So, by obtaining two encryptions of the flag under two different public exponents, we can use this attack to recover the flag with good enough probability.

```py
from pwn import *
from Crypto.Util.number import long_to_bytes
import math
import time
import random

def go():
    def get_enc_flag():
        e = random.randint(1, n)
        while math.gcd(e, 6) != 1:
            e = random.randint(1, n)
        conn.sendlineafter(b'option: ', b'1')
        return e, int(conn.recvline().decode().strip().split('flag: ')[1], 16)

    conn = remote('be.ax', 31124)
    random.seed(int(time.time()))

    conn.recvline()
    n = int(conn.recvline().decode().strip().split('is: ')[1])
    e1, c1 = get_enc_flag()
    e2, c2 = get_enc_flag()
    _, k1, k2 = xgcd(e1, e2)
    flag = pow(c1, k1, n) * pow(c2, k2, n)
    flag = long_to_bytes(int(flag))
    if b'cor' in flag:
        print(flag.decode())
        exit()
    conn.close()

while True:
    go()

# corctf{y34h_th4t_w4snt_v3ry_h1dd3n_tbh_l0l}
```

# generous <a name="generous"></a>

> Let me introduce you to this nice oracle I found...
> 
> `nc be.ax 31244`

`generous.py`:

```py
#!/usr/local/bin/python
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from random import randrange

with open("flag.txt", "rb") as f:
	flag = f.read().strip()

def gen_keypair():
	p, q = getPrime(512), getPrime(512)
	n = (p**2) * q
	while True:
		g = randrange(2, n)
		if pow(g, p-1, p**2) != 1:
			break
	h = pow(g, n, n)
	return (n, g, h), (g, p, q)

def encrypt(pubkey, m):
	n, g, h = pubkey
	r = randrange(1, n)
	c = pow(g, m, n) * pow(h, r, n) % n
	return c

def decrypt(privkey, c):
	g, p, q = privkey
	a = (pow(c, p-1, p**2) - 1) // p
	b = (pow(g, p-1, p**2) - 1) // p
	m = a * inverse(b, p) % p
	return m

def oracle(privkey, c):
	m = decrypt(privkey, c)
	return m % 2

pub, priv = gen_keypair()
n, g, h = pub
print(f"Public Key:\n{n = }\n{g = }\n{h = }")
print(f"Encrypted Flag: {encrypt(pub, bytes_to_long(flag))}")
while True:
	inp = int(input("Enter ciphertext> "))
	print(f"Oracle result: {oracle(priv, inp)}")
```

## Solution

The cryptosystem implemented in this challenge is the [Okamoto-Uchiyama cryptosystem](https://en.wikipedia.org/wiki/Okamoto%E2%80%93Uchiyama_cryptosystem). A new public-private key pair is generated for each connection and we are given the encrypted flag. We have unlimited access to a decryption least significant bit oracle. This setting feels similar to an RSA LSB oracle which can be used to decrypt an arbitrary ciphertext. Using similar ideas, we'll see that we can use the oracle in this challenge to recover the private key.

We note that decryption reduces the message modulo $p$ (in this cryptosystem, the public modulus is $n = p^2 q$ where $p$ and $q$ form the private key). This is useful as it means the result of decryptions of known plaintexts will help us gather information about $p$. 

We will denote the oracle as $\mathcal{O}$. Specifically, we have

$$
\mathcal{O}(c) =
\begin{cases}
    1, \qquad \text{if } \mathrm{decrypt}(c) \text{ is odd} \\
    0, \qquad \text{otherwise}
\end{cases}
$$

Suppose we have a message $m < p$. Let's consider what information we get about $p$ from the oracle result of $\mathcal{O}(\mathrm{encrypt}(2m))$. If the oracle returns $1$, then we must have $p < 2m$ since $p$ is odd. If the oracle returns $0$, then we must have $2m < p$ (the reduction does nothing and the result is still even). Therefore, we can use a binary search approach to narrow down the interval $p$ may lie in.

```py
from pwn import *
from Crypto.Util.number import long_to_bytes, inverse
import random

def encrypt(pubkey, m):
	n, g, h = pubkey
	r = random.randrange(1, n)
	c = pow(g, m, n) * pow(h, r, n) % n
	return c

def decrypt(privkey, c):
	g, p, q = privkey
	a = (pow(c, p-1, p**2) - 1) // p
	b = (pow(g, p-1, p**2) - 1) // p
	m = a * inverse(b, p) % p
	return m

def oracle(c):
	conn.sendlineafter(b'> ', str(c).encode())
	return int(conn.recvline().decode().strip().split('result: ')[1])

conn = remote('be.ax', 31244)
conn.recvline()
n = int(conn.recvline().decode().strip().split('n = ')[1])
g = int(conn.recvline().decode().strip().split('g = ')[1])
h = int(conn.recvline().decode().strip().split('h = ')[1])
flag_enc = int(conn.recvline().decode().strip().split('Flag: ')[1])
pubkey = (n, g, h)

U = 2**511
L = 0
i = 1
while i < 512:
	my_m = (U + L) // 2
	my_c = encrypt(pubkey, 2 * my_m)
	b = oracle(my_c)
	if b:
		U = (L + U) // 2
	else:
		L = (U + L) // 2
	print(i, L, U)
	i += 1

p = 2 * L + 1
q = n // (p*p)
privkey = (g, p, q)
flag = decrypt(privkey, flag_enc)
print(long_to_bytes(flag).decode())

# corctf{see?1_bit_is_very_generous_of_me}
```

# leapfrog <a name="leapfrog"></a>

> <img src="./assets/msfrog.png"></img>

`leapfrog.py`:

```py
from Crypto.Util.number import long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from secrets import randbelow
from random import sample

p = getPrime(256)
a = randbelow(p)
b = randbelow(p)
s = randbelow(p)

def f(s):
    return (a * s + b) % p

jumps = sample(range(3, 25), 12)
output = [s]
for jump in jumps:
    for _ in range(jump):
        s = f(s)
    output.append(s)

print(jumps)
print(output)

flag = open("flag.txt", "rb").read()
key = sha256(b"".join([long_to_bytes(x) for x in [a, b, p]])).digest()[:16]
iv = long_to_bytes(randbelow(2**128))

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
print(iv.hex() + cipher.encrypt(pad(flag, 16)).hex())
```

## Solution

In this challenge, we are given non-consecutive (but at known distances) outputs of an LCG where we know none of the parameters $(a, b, p)$. There is a lot of literature on how to deal with the case of consecutive outputs, but I couldn't find much about non-consecutive outputs, so let's do a bit of thinking. Again, we will define $f(s) = as + b \pmod p$.

Let $j_i$ be the $i$th jump value, so $j_0 = 5, j_1 = 3$, and so on. Let $S_i$ be the sum of the jump values up to (but not including) the $i$th, so $S_0 = 0, S_1 = 5, S_2 = 8$, and so on. Note that the $i$th output, which we will denote as $z_i$, is given by $f^{S_i}(s)$. The first goal will be to recover the modulus $p$. To do this, we will try to find two expressions which are $0 \pmod p$, and then take their gcd. Our approach is to find two different ways to express the same value (mod $p$).

An interesting observation is that dividing differences of the $f^{S_i}(s)$ expressions sometimes gives an expression of the form $a^t$. For example,

$$
\frac{f^{S_9}(s) - f^{S_6}(s)}{f^{S_3}(s) - f^{S_1}(s)} = a^{69}
$$

We can enumerate all such expressions to find others which give a nice power of $a$:

```py
jumps = [5, 3, 23, 13, 24, 6, 10, 9, 7, 4, 19, 16]

def f(i):
    return a^i * s + b * sum(a^j for j in range(i))

P.<a, s, b> = PolynomialRing(QQ)
S = [0] + [sum(jumps[:i]) for i in range(1, len(jumps) + 1)]
Z = [f(s) for s in S]

good = []
for i1, i2, i3, i4 in Combinations(range(len(Z)), 4):
    f_ = (Z[i4] - Z[i3])/(Z[i2] - Z[i1])
    if f_.denominator() == 1 and len(P(f_).coefficients()) == 1:
        good.append((f_, i1, i2, i3, i4))

print(good)
"""
[(a^69, 1, 3, 6, 9),
 (a^79, 1, 4, 7, 11),
 (a^95, 1, 4, 9, 12),
 (a^92, 2, 3, 9, 11),
 (a^60, 2, 4, 5, 10),
 (a^49, 4, 6, 8, 11),
 (a^55, 5, 7, 11, 12),
 (a^30, 6, 8, 10, 11),
 (a^39, 7, 9, 11, 12)]
"""
```

Now, noting that $a^{69} = a^{30} a^{39}$, we have the following relation:

$$
\begin{aligned}
    \frac{f^{S_9}(s) - f^{S_6}(s)}{f^{S_3}(s) - f^{S_1}(s)} = \frac{f^{S_{11}}(s) - f^{S_{10}}(s)}{f^{S_8}(s) - f^{S_6}(s)} \frac{f^{S_{12}}(s) - f^{S_{11}}(s)}{f^{S_9}(s) - f^{S_7}(s)} &\pmod p  \\
    \implies (f^{S_9}(s) - f^{S_6}(s))(f^{S_8}(s) - f^{S_6}(s))(f^{S_9}(s) - f^{S_7}(s)) \\
    -\ (f^{S_3}(s) - f^{S_1}(s))(f^{S_{11}}(s) - f^{S_{10}}(s))(f^{S_{12}}(s) - f^{S_{11}}(s)) = 0 &\pmod p \\
    \implies (z_9 - z_6)(z_8 - z_6)(z_9 - z_7) - (z_3 - z_1)(z_{11} - z_{10})(z_{12} - z_{11}) = 0 &\pmod p
\end{aligned}
$$

We can do the same thing noting that $a^{60} = a^{30} a^{30}$ to obtain another value that is $0$ mod $p$. By taking their gcd and removing small factors, we can recover $p$.

Once we have $p$, we can use two outputs and solve a system of equations in two variables to recover $a$ and $b$.

```py
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from sage.matrix.matrix2 import Matrix

def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))

jumps = [5, 3, 23, 13, 24, 6, 10, 9, 7, 4, 19, 16]
outputs = [26242498579536691811055981149948736081413123636643477706015419836101346754443, 30320412755241177141099565765265147075632060183801443609889236855980299685595, 65684356693401962957802832810273549345608027337432965824937963429120291339333, 15025547765549333168957368149177848577882555487889680742466312084547650972663, 46764069432060214735440855620792051531943268335710103593983788232446614161424, 71575544531523096893697176151110271985899529970263634996534766185719951232899, 8149547548198503668415702507621754973088994278880874813606458793607866713778, 12081871161483608517505346339140143493132928051760353815508503241747142024697, 65627056932006241674763356339068429188278123434638526706264676467885955099667, 23413741607307309476964696379608864503970503243566103692132654387385869400762, 56014408298982744092873649879675961526790332954773022900206888891912862484806, 77000766146189604405769394813422399327596415228762086351262010618717119973525, 14589246063765426640159853561271509992635998018136452450026806673980229327448]
ct = bytes.fromhex('05ac5b17c67bcfbf5c43fa9d319cfc4c62ee1ce1ab2130846f776e783e5797ac1c02a34045e4130f3b8111e57397df344bd0e14f3df4f1a822c43c7a89fd4113f9a7702b0b0e0b0473a2cbac25e1dd9c')

def f(i):
    return a^i * s + b * sum(a^j for j in range(i))

P.<a, s, b> = PolynomialRing(QQ)
S = [0] + [sum(jumps[:i]) for i in range(1, len(jumps) + 1)]

z = outputs
h1 = (z[9] - z[6]) * (z[8] - z[6]) * (z[9] - z[7]) - (z[11] - z[10]) * (z[12] - z[11]) * (z[3] - z[1])
h2 = (z[10] - z[5]) * (z[8] - z[6])^2 - (z[11] - z[10]) ^ 2 * (z[4] - z[2])
p = ZZ(gcd(h1, h2))
for d in range(2, 0x1000):
    while p % d == 0:
        p //= d
assert p.is_prime()
s = outputs[0]

P.<a, b> = PolynomialRing(GF(p))
f1 = f(S[1]) - outputs[1]
f2 = f(S[2]) - outputs[2]
h1 = resultant(f1, f2, b)
h2 = resultant(f1, f2, a)
a = h1.univariate_polynomial().roots()[0][0]
b = h2.univariate_polynomial().roots()[0][0]

key = sha256(b"".join([long_to_bytes(int(x)) for x in [a, b, p]])).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv=ct[:16])
flag = unpad(cipher.decrypt(ct[16:]), 16)
print(flag.decode())

# corctf{:msfrog:_is_pr0ud_0f_y0ur_l34pfr0gg1ng_4b1lit135}
```

# threetreasures <a name="threetreasures"></a>

> Let's find the treasures of three amongst the order of three.

`source.py`:

```py
from sage.all import *
from Crypto.Util.number import bytes_to_long, getPrime
from random import getrandbits
from secret import flag, p, x, y

def random_pad(n, length):
    return (n << (length - n.bit_length())) + getrandbits(length - n.bit_length())

flag = bytes_to_long(flag)
fbits = flag.bit_length()
piece_bits = fbits // 3
a, b, c = flag >> (2 * piece_bits), (flag >> piece_bits) % 2**piece_bits, flag % 2**piece_bits
print(f'flag bits: {fbits}')
assert p.bit_length() == 512
q = getPrime(512)
n = p * q
ct = pow(random_pad(c, 512), 65537, n)
E = EllipticCurve(GF(p), [a, b])
G = E(x, y)
assert G * 3 == E(0, 1, 0)
print(f"n = {n}")
print(f"ct = {ct}")
print(f"G = {G}")
```

## Solution

The flag in this challenge is 375 bits and is broken up into three pieces, one of which is encrypted with RSA and two which are used as constants for an elliptic curve. Specifically, the flag is broken up into $a, b, c$ where $a$ is the upper 125 bits of the flag, $b$ is the middle 125 bits, and $c$ is the lower 125 bits. A fixed secret 512 bit prime $p$ is multiplied by a randomly generated 512 bit prime $q$ to get an RSA modulus $n$ which we are given. We are given the ciphertext of $c$ (padded to 512 bits) encrypted with RSA under the public key $(n, 65537)$. The other two parts of the flag are used to form the elliptic curve $E : y^2 = x^3 + ax +b \pmod p$ of which we are given a point $G$ of order $3$.

The point $G$ being order $3$ is interesting because it implies that $2G = -G$ (so $(2G)_x = -G_x$). So, from the point doubling formula, we must have

$$
\begin{aligned}
    \left (\frac{3G_x^2 + a}{2G_y} \right )^2 - 2G_x &= -G_x \pmod p \\
    \implies (3G_x^2 + a)^2 &= 12 G_x G_y^2 \pmod p \\
    \implies (3G_x^2 + a)^2 - 12 G_x G_y^2 &= 0 \pmod p
\end{aligned}
$$

We know $G_x$ and $G_y$, so the only unknowns in this expression are $a$ and $p$. However, $a$ is small (relative to $p$), and $p$ is a divisor of a value we know. So Coppersmith comes to mind :) Since the bounds are quite tight, we can also use the fact that $a$ is the upper bits of the flag, and so we know a good portion of it from the flag format.

With this, we have recovered $a$. We can plug $a$ into the polynomial we just solved and compute the gcd of the result with $n$ to recover $p$. We can recover $b$ simply using the point $G$ and the elliptic curve's Weierstrass equation. Decrypting the RSA ciphertext and removing the padding to recover $c$ gives us the last piece of the flag.

```py
from Crypto.Util.number import bytes_to_long, long_to_bytes

fbits = 375
n = 97915144495462666300795364589570761584322186881492143950078938328867290046424857019504657598883431857075772605985768551863478086544857915637724181292135280539943713583281151707224031808445390796342632369109562433275679473233398168787639940620683354458292117457239552762694657810883738834935391913698852811737
ct = 20363336204536918055183609604474634074539942561101208682977506918349108499764147141944713060658857301108876346227077713201766486360148051069618774935469969057808945271860025712869868421279488925632657486125211168314387620225601572070169746014988350688548088791906161773656057212229972967244998930356157725393
Gx, Gy = (3115938227771961657567351113281194074601897467086373590156577019504528350118731801249444974253028485083440228959842232653488953448859690520619223338133881, 2665631524518629436093690344927156713668794128141943350227439039472817541262750706395352700109556004195261826476428128993836186741129487842876154876730189)

P.<a_> = PolynomialRing(Zmod(n))
a_k = bytes_to_long('corctf{'.encode()) << 70
f=(3*Gx^2 + a_k + a_)^2 - 12 * Gx*Gy^2
a_u = f.small_roots(X=2^70, beta=0.5)[0]
a = a_k + a_u
kp = (3*Gx^2 + a)^2 - 12*Gx*Gy^2
p = gcd(kp, n)
assert p.is_prime()
b = (Gy^2 - Gx^3 - a*Gx) % p
q = n//int(p)
d = pow(0x10001, -1, (p-1)*(q-1))
m = pow(ct, int(d), n)
c = m >> (512 - 125)
flag = (int(a) << (2*125)) | (int(b) << 125) | int(c)
print(long_to_bytes(flag).decode())

# corctf{you_have_conquered_the_order_of_three!!}
```

# rlfsr <a name="rlfsr"></a>

> humans may be bad at generating random numbers, but they can shuffle cards well enough!

`rlfsr.py`:

```py
from secrets import randbits
from random import shuffle
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class LFSR:
    def __init__(self, key, taps):
        self.key = key
        self.taps = taps
        self.state = list(map(int, list("{:0128b}".format(key))))
    
    def _clock(self):
        ob = self.state[0]
        self.state = self.state[1:] + [sum([self.state[t] for t in self.taps]) % 2]
        return ob

key = randbits(128)
l = LFSR(key, [1, 2, 7, 3, 12, 73])
out = []

for i in range(118):
    bits = [l._clock() for _ in range(128)]
    shuffle(bits)
    out += bits

print(hex(sum([bit*2**i for i, bit in enumerate(out)])))

flag = open("flag.txt", "rb").read()
iv = randbits(128).to_bytes(16, 'big')
aeskey = sha256(key.to_bytes(16, 'big')).digest()[:32]
print((iv + AES.new(aeskey, AES.MODE_CBC, iv=iv).encrypt(pad(flag, 16))).hex())
```

## Solution

We have a very standard LFSR setup, except the output stream we are given is shuffled in blocks. The key is 128 bits and we are given 118 chunks of 128 consecutive, but shuffled LFSR outputs. The main idea is to ignore the shuffling and use each chunk of 128 bits as one relation among the key bits. We can do that by summing all of the bits in each chunk since the order doesn't matter if all we care about is the sum. Doing this gives us 118 relations in the 128 key variables. It's quite quick to solve the system so we can bruteforce the remaining bits to have enough relations to recover the key.

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from tqdm import tqdm

class LFSR:
    def __init__(self, key, taps):
        self.taps = taps
        self.state = key
    
    def _clock(self):
        ob = self.state[0]
        self.state = self.state[1:] + [sum([self.state[t] for t in self.taps])]
        return ob

def check_ans(G):
    key = int(''.join([str(z.constant_coefficient()) for z in G]), 2)
    key = sha256(key.to_bytes(16, 'big')).digest()[:32]
    dec = AES.new(key, AES.MODE_CBC, iv=ct[:16]).decrypt(ct[16:])
    if b'cor' in dec:
        print(unpad(dec, 16).decode())

output = open('./output.txt', 'r').read().splitlines()
stream = list(map(int, f'{int(output[0], 16):015104b}'))[::-1]
ct = bytes.fromhex(output[1])

B = BooleanPolynomialRing(128, [f'k{i}' for i in range(128)])
kvars = list(B.gens())
L = LFSR(kvars, [1, 2, 7, 3, 12, 73])

print('building equations...')
eqs = []
for i in tqdm(range(118)):
    l = [L._clock() for _ in range(128)]
    r = sum(stream[i * 128 : (i + 1) * 128]) % 2
    eqs.append(sum(l) - r)

for z in tqdm(range(2**11)):
    bf = [kvars[i] - ((z >> i) & 1) for i in range(11)]
    G = Ideal(eqs + bf).groebner_basis()
    if len(G) == 128:
        check_ans(G)

# corctf{m4yb3_w3_sh0uld_ju5t_cut_hum4n5_0ut_0f_th1s_c0mpl3t3ly_1f_th3y_d3c1d3_t0_f4k3_shuffl3_0r_s0m3th1ng}
```

# corrupted-curves(+) <a name="corrupted-curves"></a>

corrupted-curves and corrupted-curves+ were an interesting set of challenges involving elliptic curves and lattices. My solution works for both challenges and uses only two outputs of the oracle. I'll present the solution to corrupted-curves+, but the solution for corrupted-curves is identical (though it suffers from a bit less reliability because the unknown part is 64 bits instead of 48).

> ok, no more being picky.
> 
> `nc be.ax 31132`

`corruptedcurvesplus.py`:

```py
#!/usr/local/bin/python
from secrets import randbits
from Crypto.Util.number import getPrime
from random import randrange

def square_root(a, p):
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)
        if m == 0:
            return x
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

class EllipticCurve:
    
    def __init__(self, p, a, b):
        self.a = a
        self.b = b
        self.p = p
        if not self.check_curve():
            raise Exception("Not an elliptic curve!")
        
    def check_curve(self):
        discrim = -16 * (4*pow(self.a, 3) + 27*pow(self.b, 2))
        if discrim % self.p:
            return 1
        return 0
    
    def lift_x(self, px):
        y2 = (pow(px, 3) + self.a*px + self.b) % self.p
        py = square_root(y2, self.p)
        if py == 0:
            raise Exception("No point on elliptic curve.")
        return py

with open("flag.txt", "rb") as f:
    flag = f.read()
    flag = int.from_bytes(flag, 'big')

print("Generating parameters...")
while True:
    p = getPrime(512)
    a, b = randbits(384), randbits(384)
    try:
        E = EllipticCurve(p, a, b)
        fy = E.lift_x(flag)
        print(f"p = {p}")
        print(f"flag y = {fy}")
        break
    except:
        continue
checked = set()
count = 0
while count < 2022:
    x = randrange(2, p)
    if int(x) in checked or x < 2**384 or abs(x - p) < 2**384:
        print(">:(")
        continue
    try:
        e = randbits(48)
        print(f"e = {e}")
        E = EllipticCurve(p, a^e, b^e)
        py = E.lift_x(x)
        checked.add(x)
        print(f"x = {x}")
        print(f"y = {py}")
        count += 1
    except:
        print(":(")
    more = input("more> ")
    if more.strip() == "no":
        break
print("bye!")
```

## Challenge Overview

We can thankfully ignore the `square_root`, `legendre_symbol` and `EllipticCurve` functions and assume they are correct with no bugs.

A random 512 bit prime $p$ is generated as well as 384 bit $a$ and $b$ to construct the elliptic curve $E : y^2 = x^3 + ax + b \pmod p$. The server will then try to find a point with the flag as the x coordinate (if it fails, the parameters are regenerated). We are given $p$ and the y coordinate of the point whose corresponding x coordinate is the flag. So, to recover the flag it seems like we need to recover $a$ and $b$.

To help us in finding $a$ and $b$, we have access to 2022 calls of an oracle which will generate a random $e \in [0, 2^{48})$ and and try construct the "corrupted" curve $E_e : y^2 = x^3 + (a \oplus e) x + (b \oplus e) \pmod p$. It will generate a random $x \in [2, p)$ and try to lift it to a point on the curve. If there are errors in this process (i.e. the curve is a valid elliptic curve and the point exists), then we get a sad face, otherwise we are given $(e, x, y)$ where $y$ is the corresponding y component on the corrupted curve.

That's about it for the setting, nice and simple! Now let's see how to recover some bits.

## Recovering the upper bits of $a$

In this solution, we will only use two outputs of the oracle, so let's call them $(e_1, x_1, y_1)$ and $(e_2, x_2, y_2)$. We have the relations

$$
\begin{aligned}
    y_1^2 &= x_1^3 + (a \oplus e_1) x_1 + (b \oplus e_1) \pmod p \\
    y_2^2 &= x_2^3 + (a \oplus e_2) x_2 + (b \oplus e_2) \pmod p \\
\end{aligned}
$$

XOR is annoying to deal with, so we can rewrite this equation with additions instead of XOR. Let's define some variables:

$$
\begin{aligned}
    e_{1,a} &= a - (a \oplus e_1) \\
    e_{1,b} &= b - (b \oplus e_1) \\
    e_{2,a} &= a - (a \oplus e_2) \\
    e_{2,b} &= b - (b \oplus e_2) \\
\end{aligned}
$$

Note that we have $a - e_{1,a} = a \oplus e_1$ (and similarly for the other three variables). We also note that $|e_{1,a}|, |e_{1,b}|, |e_{2,a}|, |e_{2,b}| < 2^{48}$. Rewriting the equations with these variables, we get

$$
\begin{aligned}
    y_1^2 &= x_1^3 + (a - e_{1, a}) x_1 + (b - e_{1, b}) \pmod p \\
    y_2^2 &= x_2^3 + (a - e_{2, a}) x_2 + (b - e_{2, b}) \pmod p \\
\end{aligned}
$$

To make it a bit easier to read, let $c_1 = y_1^2 - x_1^3$ and $c_2 = y_2^2 - x_2^3$, then we have

$$
\begin{aligned}
    c_1 &= (a - e_{1, a}) x_1 + (b - e_{1, b}) \pmod p \\
    c_2 &= (a - e_{2, a}) x_2 + (b - e_{2, b}) \pmod p \\
\end{aligned}
$$

It will be helpful if we can eliminate unknowns, so let's take the difference of these two expressions to get rid of $b$. We get one expression:

$$
c_2 - c_1 = (a - e_{2, a}) x_2 - (a - e_{1, a}) x_1 + (e_{1, b} - e_{2, b}) \pmod p
$$

Now, let's split up $a$ into two parts, namely, into the lower 48 bits $a_l$ and the upper $384 - 48 = 336$ bits $a_u$. So, we have $a = 2^{48} a_u + a_l$. The reason we do this is to reduce the number of bits that we'll try to recover. Let's rewrite the equation again and things will become more clear:

$$
\begin{aligned}
    c_2 - c_1 &= (2^{48} a_u + a_l - e_{2, a}) x_2 - (2^{48} a_u + a_l - e_{1, a}) x_1 + (e_{1, b} - e_{2, b}) \pmod p \\
    \implies  &= 2^{48} a_u (x_2 - x_1) + x_2(a_l - e_{2,a}) + x_1(e_{1,a} - a_l) + (e_{1,b} - e_{2,b}) \pmod p
\end{aligned}
$$

Now, we note the sizes of each of the unknown parts of this expression. $a_u$ is $336$ bits, $(a_l - e_{2,a}), (e_{1,a} - a_l), (e_{1,b} - e_{2,b})$ are all $48$ bits. All together, thats $480$ bits of unknowns. It seems like a lot, but it turns out we can recover everything. You could actually recognise this as an [extended hidden number problem](https://link.springer.com/chapter/10.1007/978-3-540-74462-7_9) instance, but its simple enough to just construct a lattice by looking at this expression.

Consider the lattice generated by the rows of the matrix $M$:

$$
M = 
\begin{bmatrix}
p & 0 & 0 & 0 & 0 \\
2^{48} (x_2 - x_1) & 1/2^{336} & 0 & 0 & 0 \\
-x_2 & 0 & 1/2^{48} & 0 & 0 \\
x_1 & 0 & 0 & 1/2^{48} & 0 \\
1 & 0 & 0 & 0 & 1/2^{48}
\end{bmatrix}
$$

Note that the vector $\mathbf{w} = (c_2 - c_1, 2^{48}a_u/2^{384}, (a_l - e_{2,a})/2^{48}, (e_{1,a} - a_l)/2^{48}, (e_{1,b} - e_{2,b})/2^{48})$ is in this lattice. It is generated by the linear combination $\mathbf{x} = (k, a_u, a_l - e_{2,a}, e_{1,a} - a_l, e_{1,b} - e_{2,b})$ (for some integer $k$). That is, $\mathbf{x} M = \mathbf{w}$. Furthmore, we also note that $\mathbf{w}$ is close to the vector $\mathbf{t} = (c_2 - c_1, 1, 1, 1, 1)$. Therefore, we can use Babai's CVP algorithm to recover $\mathbf{w}$ from which we can read off $a_u$ and recover the upper bits of $a$!

### Side note about SVP

We used CVP to recover $a_u$ (because it's easier to understand?), but we can also use SVP to achieve the same thing. We do this by embedding the target into the lattice basis. In doing this, we must increase the dimension by one. We get the basis

$$
\begin{bmatrix}
p & 0 & 0 & 0 & 0 & 0 \\
2^{48} (x_2 - x_1) & 1/2^{336} & 0 & 0 & 0 & 0 \\
-x_2 & 0 & 1/2^{48} & 0 & 0 & 0 \\
x_1 & 0 & 0 & 1/2^{48} & 0 & 0 \\
1 & 0 & 0 & 0 & 1/2^{48} & 0 \\
-(c_2 - c_1) & 0 & 0 & 0 & & 1
\end{bmatrix}
$$

Now, note that the linear combination $(k, a_u, a_l - e_{2,a}, e_{1,a} - a_l, e_{1,b} - e_{2,b}, 1)$ generates the (short?) vector $\mathbf{w'} = (0, 2^{48}a_u/2^{384}, (a_l - e_{2,a})/2^{48}, (e_{1,a} - a_l)/2^{48}, (e_{1,b} - e_{2,b})/2^{48})$. It turns out that this vector is pretty short; its length is quite close to $1$. In fact, the only nonzero lattice point shorter than it is $(1, 0, 0, 0, 1/2^{48}, 0)$ (which happens to be one of the basis vectors). Running LLL on this basis will reveal $\mathbf{w}'$ in the second vector of the reduced basis.

## Recovering the lower bits of $a$

We have the upper $336$ bits of $a$ but we need all of the bits of $a$ and the remaining $48$ bits is too much to bruteforce. Fortunately, while we were busy recovering $a_u$, we also obtained some useful relations about $a_l$. Recall the vector we covered with CVP:

$$
\mathbf{w} = (c_2 - c_1, 2^{48}a_u/2^{384}, (a_l - e_{2,a})/2^{48}, (e_{1,a} - a_l)/2^{48}, (e_{1,b} - e_{2,b})/2^{48})
$$

By multiplying the fourth entry by $2^{48}$, we obtain $e_{1,a} - a_l$. Looking back at the definition of $e_{1,a} = a - (a \oplus e_1)$, we note that this also holds for just the lower $48$ bits. That is, $e_{1,a} = a_l - (a_l \oplus e_1)$. And since we have $e_{1,a} - a_l$ and $e_1$, we can recover $a_l$ by computing $a_l = -(e_{1,a} - a_l) \oplus e_1$.

## Recovering $b$

With that, we've fully recovered $a$! It's easy to recover $b$ using just one of the outputs by solving for $b$ in the equation

$$
\begin{aligned}
    y_1^2 &= x_1^3 + (a \oplus e_1) x_1 + (b \oplus e_1) \pmod p \\
    \implies b &= (y_1^2 - x_1^3 - (a \oplus e_1) x_1) \oplus e_1 \pmod p
\end{aligned}
$$

## Recovering the flag

Where $f_x$ is the flag and $f_y$ is the corresponding y coordinate on the elliptic curve $E : y^2 = x^3 + ax + b \pmod p$, we can recover $f_x$ by finding the roots of

$$
x^3 + ax + b - f_y^2 = 0 \pmod p
$$

That's it!

```py
from pwn import *
from Crypto.Util.number import long_to_bytes

def babai_cvp(B, t):
    B = B.LLL(delta=0.75)
    G = B.gram_schmidt()[0]
    b = t
    for i in reversed(range(B.nrows())):
        c = ((b * G[i]) / (G[i] * G[i])).round()
        b -= c * B[i]
    return t - b

def do_round():
    e = int(conn.recvline().decode().strip().split('e = ')[1])
    o = conn.recvline().decode().strip()
    if o == ':(':
        return e, False, False
    x = int(o.split('x = ')[1])
    y = int(conn.recvline().decode().strip().split('y = ')[1])
    return e, x, y

conn = remote('be.ax', 31132)

conn.recvline()
p = int(conn.recvline().decode().strip().split('p = ')[1])
flag_y = int(conn.recvline().decode().strip().split('flag y = ')[1])

outs = []
while True:
    e, x, y = do_round()
    if x:
        outs.append((e, x, y))
    conn.sendlineafter(b'more> ', b'ye' if len(outs) < 2 else b'no')
    if len(outs) >= 2:
        break

(e1, x1, y1), (_, x2, y2) = outs

c1 = (y1^2 - x1^3) % p
c2 = (y2^2 - x2^3) % p
M = [[p, 0, 0, 0, 0],
     [2^48 * (x2 - x1) % p, 1/2^336, 0, 0, 0],
     [-x2, 0, 1/2^48, 0, 0],
     [x1, 0, 0, 1/2^48, 0],
     [1, 0, 0, 0, 1/2^48]]
M = Matrix(M)
w = babai_cvp(M, vector(QQ, [(c2 - c1) % p, 1, 1, 1, 1]))
a_u = int(w[1]*2^384)
a_l = int(e1) ^^ int(-w[3]*2^48)

a = int(a_u + a_l)
b_xor_e1 = (y1^2 - x1^3 - (a^^e1) * x1) % p
b = b_xor_e1^^e1
P.<flag_x> = PolynomialRing(GF(p))
f = flag_y^2 - flag_x^3 - a*flag_x - b
roots = f.roots()
for r, _ in roots:
    flag = long_to_bytes(int(r))
    if b'cor' in flag:
        print(flag.decode())

# corctf{cr4ftin6_f3as1ble_brut3s_unt1l_y0u_mak3_it!}
```
