---
path: /posts/2020-09-07-codegate-ctf-2020-finals-writeups
title: Codegate CTF 2020 Finals Writeups
date: 2020-09-07
tags: ctf,infosec,writeup,crypto
---

As a disclaimer, I didn't participate in this CTF. I just found this challenge online and thought it was fun.

- crypto
    - [cloud9](#cloud9)

---

# cloud9 <a name="cloud9"></a>

> We've been tricked, we've been backstabbed and we've been quite possibly, bamboozled.

`chall.sage`:

```python
#!/usr/bin/env sage
from secret import P1, Q1, a, b
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

P0 = P1 & ord('?')
Q0 = Q1 & ord('?')
assert is_prime(P0) and is_prime(P1)
assert is_prime(Q0) and is_prime(Q1)


class Chall:

    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.E  = EllipticCurve(Zmod(self.n), [a, b])
        self.E1 = EllipticCurve(Zmod(p), [a, b])

        # Not Implemented, but you get the point :D
        self.G = E.random_point()
        self.d = randint(1, 1 << 128) & (p >> 1)
        self.Q = self.d * self.G

    def expose(self):
        print(self.n)
        print(self.E1.order())
        print(self.G.xy())
        print(self.Q.xy())

    def getkey(self):
        return self.d


if __name__ == '__main__':
    s = Chall(P0, Q0)
    s.expose()
    sd = s.getkey()

    l = Chall(P1, Q1)
    l.expose()
    ld = l.getkey()

    size = 16
    flag = pad(open('flag.txt', 'rb').read(), size)

    key = int(sd + ld)
    key = key.to_bytes(size, byteorder='big')
    cipher = AES.new(key, AES.MODE_ECB)
    enc_flag = cipher.encrypt(flag).hex()

    print(enc_flag)
```

## Solution

The challenge encrypts the flag with AES using a key derived from some large secret number. To recover the secret number, we need to solve the ECDLP. The challenge comes in two parts: recovering the unknown curve parameters, and solving the ECDLP.

### Analysis

The `Chall` class is initialised with two (prime) numbers $p$ and $q$. It selects a random point $G$ on the curve $E(\mathbb{Z}/pq\mathbb{Z})$ and a random 128 bit number $d$ as the private key. We are given $N = pq$, the order of $E(\mathbb{F}_p)$, the random point $G$, and the point given by $dG$.

### Part 1: Recovering the Unknown Curve Parameters

Points on the curve are related by the equation

$$
y^2 \equiv x^3 + ax + b \pmod N
$$

We are given 2 points $(x_1, y_1)$ and $(x_2, y_2)$ on the curve, so we can solve for $a$ and $b$:

$$
\begin{aligned} a &\equiv (y_2^2 - x_2^3 + x_1^3 - y_1^2)(x_2 - x_1)^{-1} \pmod N \\ b &\equiv y_1^2 - x_1^3 - ax_1 \pmod N \end{aligned}
$$

We notice that the order of $E(\mathbb{F}_p)$ is rather smooth! If we can recover $p$, we should be able to solve the ECDLP in $E(\mathbb{F}_p)$.

So the goal for now is to recover $p$. Curiously, we are given $n = \#E(\mathbb{F}_p)$. It turns out that this is actually a pretty good estimate for $p$. In fact, on average the top 128 MSB of $n$ are the same as the top 128 MSB of $p$. (Here $p$ is around 256 bits). We know that, as a general rule of thumb, whenever we have a good amount of bits of a number we're trying to find, we can usually apply Coppersmith's theorem to recover the number completely (given some other information, of course). We're actually also given the bottom 6 LSB of $p$ with the call to `s.expose()` since we can easily factor $N$ in that case and deduce that `p & 0b111111 == 37`. So we have just over half the bits of $p$.

Let $t$ be the top ~128 bits of $n$. We know that $N = pq$, and $p \approx t + 37$. Now, construct the univariate polynomial in $\mathbb{Z}/N\mathbb{Z}$

$$
f(x) \equiv t + 2^{6}x + 37 \pmod N
$$

$f$ will have a root $|\delta| < 2^{122}$ (modulo $p$).

We can recover $p$ by computing

$$
p = t + 2^6 \delta + 37
$$

### Part 2: Solving the ECDLP

As mentioned before, the order of $E(\mathbb{F}_p)$ is rather smooth. We are given this in the challenge output, so we are pretty much guided on how to proceed. This is the prime factorisation of the order `n`:

```
2^3 * 3^4 * 13 * 151 * 37277 * 63737 * 743689 * 14743331 * 20904431 * 3659465143 * 38635749385473505471502894387389
```

Most of the factors are small, except the large 105 bit factor. Luckily for us, the secret multiplier `d` is only 128 bits! Excluding the large 105 bit factor, the product of the other factors is more than 128 bits. We can solve the ECDLP in these subgroups and combine the results using the Chinese Remainder Theorem to get the secret multiplier. See [here](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) for details.

### Grabbing the Flag

The value of `sd` is less than `37 >> 1` so we can trivially bruteforce it. All we need to do is decrypt the flag and check which decryption contains the flag format.

**Solve script:**

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

N = 5836992596022446937012188954528837967652088799787297418688161952734029742601918639776384293816907277293165804095447608755394244018171460874413413360601287
ZN = Zmod(N)
n = 97940012926710762153437884674079301076079191877203953722437921714333988067208
G = (4791064145174837833113077069599757584947381216841105432787931481123835537923996904590176334618000141035959257993847069760040827648845993882710813263422518, 2007135516277895026771627676893419200766568709594031697039637947675097596595809713825936430608820664600227626467013163201670055105153466868380086912003923)
Q = (2906660915459424515040277093002683642589488507112805139726386938933880929506501185082819430093812825540133325640097413100449877310669418449600698325701077, 3812143203765395705358551712573539116980648501774991245491977901798688330759954052153901303962483747022229555022370548381218346760417689877969168781021420)
ct = bytes.fromhex('f512c0de4f899ac8d8e6481f2f9b9df22f0cd05f50f9d42750be913156bb27ea5a141f014082853aa97341499ca74d84')

x1,y1 = G
x2,y2 = Q
a = ZN((y2^2 - x2^3 + x1^3 - y1^2)/(x2-x1))
b = ZN(y1^2 - x1^3 - a*x1)
print('[+] a recovered:', a)
print('[+] b recovered:', b)

P.<x> = PolynomialRing(ZN, implementation='NTL')
poly = (n - (n % 2^124)) + 2^6 * x + 37
poly = poly.monic()
delta = poly.small_roots(X=2^122, beta=0.5, epsilon=1/84)[0]
p = (n - (n % 2^124)) + 2^6 * delta + 37
print('[+] p recovered:', p)

E = EllipticCurve(GF(p), [a, b])
G = E(G)
Q = E(Q)

factors = (n//(2^3 * 3^4 * 38635749385473505471502894387389)).factor()
factors = [f for f,_ in factors]

K = []
for pi in factors:
    qi = int(n//pi)
    Pi = qi*G
    Qi = qi*Q
    print('[*] computing discrete log for subgroup of order', pi)
    K.append(discrete_log(Qi, Pi, operation='+'))
d = crt(K, factors)
print('[+] private key recovered:', d)

for sd in range(37 >> 1):
    key = int(sd + d)
    key = key.to_bytes(16, byteorder='big')
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.decrypt(ct)
    if b'CODEGATE' in flag:
        print(unpad(flag, 16).decode())
        exit()
```

Flag: `CODEGATE2020{Here_comes_the_crypto_genius}`
