---
path: /posts/2021-07-19-google-ctf-2021-crypto-writeups
title: Google CTF 2021 - Crypto
date: 2021-07-19
tags: ctf,infosec,writeup,crypto
---

I participated in Google CTF on team 🛹🐻 and we placed #13! It was nice having teammates to solve the crypto challenges with. I worked on all of the crypto challenges throughout the CTF but only solved Tiramisu, Pythia and H1 (with the help of teammates). My teammates solved Story and Tonality but I've written writeups for completeness.

---

|Challenge|Tags|Points|Solves|
|---|---|---|---|
|[Tiramisu](#tiramisu)|`ECDH` `invalid curve attack`|263|28|
|[Pythia](#pythia)|`AES-GCM` `partitioning oracle`|173|65|
|[Story](#story)|`CRC` `black box` `affine`|249|32|
|[Tonality](#tonality)|`ECDSA`|256|30|
|[H1](#h1)|`ECDSA` `bad nonce` `LLL`|283|23|

# Tiramisu <a name="tiramisu"></a>

> In this challenge, you establish a secure channel with the server.
> 
> Good luck!
> 
> [attachment](https://storage.googleapis.com/gctf-2021-attachments-project/ac92228c49e4a4da943b643b35fe8e824603a2a99b3cbd1376db48ffdbcc9a9b9a19d5c5bb6c3afe6f1b43bb9a1c64fd70208c71950743ed677afe6e3f723203) `tiramisu.2021.ctfcompetition.com 1337`

## Initial Observations

We are given the code running on a server and some client code to interact with the server. The server is written in [Go](https://golang.org/) and performs key exchanges using [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman). The server and client use protobuf to exchange data, but this is handled for us in the given client code so we can ignore it.

The interaction between the client and server is simple; when the client connects, the server sends its public key and the flag encrypted with its private key. The client then sends its public key and an encrypted and authenticated message. The server attempts to decrypt and verify the ciphertext, and if successful, encrypts the message and echoes it back to the client.

Upon analysing the code, we noticed:
- `server_main.go:118`: the server reads its private key and curve from a file; it is the same for every interaction (the public key and encrypted flag don't change even if we reconnect)
- `pb_util.go:25`: the server only supports curves `secp224r1` and `secp256r1`; attempting to use any other curve causes the server to disconnect
- `server.go:104`: the server ensures that the client provided public key point is on the curve specified by the client; this means our point must be on either `secp224r1` or `secp256r1`
- [`crypto/elliptic/elliptic.go:73`](https://cs.opensource.google/go/go/+/refs/tags/go1.16.6:src/crypto/elliptic/elliptic.go;l=73): the `IsOnCurve` check will pass even if the coordinates `x` and `y` lie outside of the range `[0, p-1]` (where `p` is the order of the finite field that the curve is defined over):
```go
func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ - 3x + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.polynomial(x).Cmp(y2) == 0
}
```
- `server.go:111`: when computing its shared secret, the server reduces the `x` and `y` coordinates of the client's public key modulo its own curve's prime (i.e. modulo `p224`)
- `cipher.go:92`: if the client provided MAC does not match the expected match computed from the server's derived shared secret, the server disconnects

And perhaps most importantly, the goal is to recover the server's static private key, but we gain no information about it other than from the last observation; the MAC we compute matches the server's expected MAC if and only if we derive the same shared secret. This means, to gain any information about the server's private key, we'll need to use it as an oracle; guessing things we think might be correct, and verifying it with the server.

## Attack Ideas

After seeing that the server checks that the client provided public key point is on the curve, it might seem that invalid curve attacks are out of the question. But it's highly suspicious that the server supports both `secp224r1` and `secp256r1`, despite only ever using `secp224r1` for its own public key, and that it reduces the client's public key point modulo `p224` regardless of the client's curve. It then continues to work with this point, scalar multiplying it by its private key. Note that only the curve parameters $a$ and $p$ are used in point addition; the curve's $b$ is not relevant for addition, but affects the order of the curve. It turns out that this is enough to mount an invalid curve attack. Specifically, if we as the client, specify that our curve is `secp256r1` and give a point on `secp256r1`, once the server reduces the coordinates modulo `p224`, it may no longer lie on `secp256r1` nor `secp224r1`.

#### The High-Level Overview

We will find points that lie on `secp256r1`, but when reduced modulo `p224`, have small order on the new curve that it lies on. We send this point as our public key, specifying curve `secp256r1` so that we pass the `IsOnCurve` check. Then, because the point has small order (when reduced modulo `p224`), when the server derives the shared secret point by scalar multiplying our small order point with its private key, there will be only a small number of possible results. Specifically, there will be up to `n` different shared secret points the server may compute, where `n` is the order of the point (when reduced modulo `p224`). We can ascertain which is the correct value by multiplying this point by values up to `n` and using this as the shared secret point. We derive the secret key from it and send an authenticated message to the server. If the server echoes a message back, we've found the correct value. This gives us the value of the server's private key modulo `n`. By doing this many times with different points and coprime `n`, we can gather enough information to recover the entire private key by combining the results with the Chinese Remainder Theorem.

#### A Slightly More Detailed Overview

We denote the curve parameters of `secp224r1` and `secp256r1` with subscripts (e.g. $p_{256}, a_{224}$, and so on..)

1. Choose a random integer $b$ and consider the curve `E_b`: $E_{a_{224},b}(\mathbb{F}_{p_{224}})$
2. Choose a random point $G$ on the curve and compute its order; hopefully, and with reasonable probability, the order has a small prime factor $n$ (small enough that we're happy to bruteforce on the remote server for: around `1000` to `60000`)
3. Let $(x, y) = \frac{|G|}{n}G$. Then, $(x, y)$ is a point on `E_b` with order `n`
4. At the moment, $(x, y)$ does not lie on `secp256r1`, but we can "lift" it to $(X, Y)$ such that it lies on `secp256r1` when reduced modulo `p256`, but equals $(x, y)$ on `E_b` when reduced modulo `p224`
5. For `i = 0..n`:
    1. Connect to the server and send $(X, Y)$ as the public key, specifying curve `secp256r1`
    2. Compute a shared secret point by multiplying $(x, y)$ by `i` (as a point on the curve `E_b`)
    3. Use the key derivation function on this point to encrypt a message and compute a MAC. Send this to the server.
    4. If the server echoes a message back, we have recovered partial information about the server's private key.
6. Repeat steps 1-5 for different values of $b$ and coprime $n$ until the product of all such $n$ exceed `p224` (the expected size of the private key)
7. Use the Chinese Remainder Theorem to recover the private key fully

There are a few details missing. We will explore the full attack in the following sections.

## Steps 1-4: Generating Good Curves and Points

Our goal is to find values $(X, Y)$ such that reduction modulo `p256` gives a valid point on `secp256r1`, and reducing modulo `p224` gives a point of small order on some insecure curve. We begin by choosing a random $b \lt p_{224}$. We then construct the curve `E_b` given by $E_{a_{224}, b}(\mathbb{F}_{p_{224}})$. We choose a random point on `E_b` and compute its order. If a small prime factor $n$ divides the order, we compute the point $P = (x, y) = \frac{|G|}{n} G$ which has order $n$. Now let

$$
\begin{aligned}
    X &= x \\
    m &= p_{224} p_{256} \\
    t &\equiv p_{224}^{-1} \pmod{p_{256}} \\
    s &\equiv p_{256}^{-1} \pmod{p_{224}} \\
    L &\equiv a_{224} p_{256} s + a_{256} p_{224} t \pmod m \\
    C &\equiv b p_{256} s + b_{256} p_{224} t \pmod m \\
    u &\equiv X^3 + LX + C \pmod m
\end{aligned}
$$

If $u$ is a quadratic residue modulo $p_{224}$ and modulo $p_{256}$ then we can write $u \equiv Y^2 \pmod m$. So

$$
Y^2 \equiv X^3+ LX + C \pmod m
$$

We can recover $y$ by computing the square roots of $u$ modulo $p_{224}$ and modulo $p_{256}$, and then combining the results with CRT.

Now, note that

$$
\begin{aligned}
    L &\equiv a_{224} \pmod{p_{224}} \\
    C &\equiv b \pmod{p_{224}}
\end{aligned}
$$

(because the $p_{224}$ factors are killed by the mod $p_{224}$, and $p_{256}s \equiv 1 \pmod{p_{224}}$).

Therefore,

$$
Y^2\equiv X^3 + a_{224}X + b \pmod{p_{224}}
$$

so the point, modulo $p_{224}$, lies on `E_b` as we wanted!

Similarly, reducing modulo $p_{256}$, we get

$$
\begin{aligned}
    L &\equiv a_{256} \pmod{p_{256}} \\
    C &\equiv b_{256} \pmod{p_{256}}
\end{aligned}
$$

so as we hoped,

$$
Y^2 \equiv X^3 + a_{256}X + b_{256} \pmod{p_{256}}
$$

So $(X, Y)$ lies on `secp256r1` when reduced modulo $p_{256}$, and lies on `E_b` when reduced modulo $p_{224}$.

The following Sage script finds such $b$ and good curves/points:

```py
def get_valid_br_point(br):
  E = EllipticCurve(GF(p224), [a224, br])
  G = E.random_point()
  n = G.order()
  for z in GOOD_PRIMES:
    if n % z == 0:
      break
  else:
    return None, None, None
  P = (n//z)*G
  m = p224*p256
  x = mod(int(P.xy()[0]), m)
  linear_coef = mod(p256*a224*inverse_mod(p256, p224) + p224*inverse_mod(p224,p256)*a256, m)
  const_coef = mod(p256*inverse_mod(p256,p224)*br + p224*inverse_mod(p224,p256)*b256, m)
  ysqr = mod(x^3 + linear_coef*x + const_coef, m)
  if kronecker(ysqr, p224) == 1 and kronecker(ysqr, p256) == 1:
    ysp224 = Integer(sqrt(mod(ysqr, p224)))
    ysp256 = Integer(pow(ysqr, (p256+1)//4, p256))
    y = mod(CRT([ysp224, ysp256], [p224, p256]), m)
    P_on_E = E(int(x) % p224, int(y) % p224)
    return (int(x), int(y)), P_on_E, z
  return None, None, None

p224 = 0xffffffffffffffffffffffffffffffff000000000000000000000001
a224 = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe

p256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a256 = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

GOOD_PRIMES = [p for p in range(2^9, 2^16) if Integer(p).is_prime()]
USED_FACTORS = []

while True:
  br = randint(1, p224)
  point, P_on_E, z = get_valid_br_point(br)
  if point is None:
    continue
  else:
    x, y = point
    if z not in USED_FACTORS:
      print(br, x, y, z)
      USED_FACTORS.append(z)
```

## Step 5: Requesting the Oracle

We modified the `run_session` function in the provided client code to take integers `x`, `y` and `shared_point`. It runs the session as usual but uses the provided `(x, y)` as the public key, specifying `secp256r1` as the curve. It derives the shared secret key from the provided `shared_point` and sends an encrypted and authenticated message. If it receives an echo reply, it returns True, otherwise, it returns False.

The following Sage function implements step 5.

```py
def exhaust_shared_point(XY, P_on_E, n):
  for k in range(1, n):
    shared_point = (k*P_on_E).xy()[0]
    X, Y = XY
    res = run_session(int(X), int(Y), int(shared_point))
    if res:
      return k
```

Because we used subgroups of sizes between `2^9` to `2^16` (why we used such large subgroups instead of smaller ones will be the topic of the next section), the bruteforce on the remote server would have taken a lot of time. To make it run faster, we ran the script on a GCP compute instance in Belgium, which is where the challenge server was located.

## Steps 6-7: Recovering the Private Key

For step 6, we simply repeat step 5 with all of the different $b$ and points we found in steps 1-4. Doing so gives us a set of $n$ residues $k_1, \ldots, k_n$ and corresponding pairwise co-prime moduli $m_1, \ldots, m_n$ such that $\prod_{i=1}^n m_i \geq p_{224}$ and

$$
\begin{aligned}
    k &\equiv k_1 \pmod{m_1} \\
    k &\equiv k_2 \pmod{m_2} \\
    \vdots \\
    k &\equiv k_n \pmod{m_n} \\
\end{aligned}
$$

where $k$ is the server's private key. This can be solved using the Chinese Remainder Theorem. However, there is a subtlety we need to consider. Because the computation of the shared secret point disregards the $y$ value of the result, there are actually two values for each $k_i$ that satisfy $k \equiv k_i \pmod{m_i}$. Specifically, if $k \equiv k_i \pmod{m_i}$, then we also have $k \equiv -k_i \pmod{m_i}$. Therefore, for each congruence we have in the system, we need to consider both values. This means we will need to perform an offline $2^n$ search. For this reason, we chose to use larger subgroup sizes to ensure the offline part does not take too long.

The following Sage script prints a list of candidate private keys using data we obtained from the previous steps:

```py
from itertools import product

p = 0xffffffffffffffffffffffffffffffff000000000000000000000001

def generate_candidates(K, M):
  candidate_K = [(k, m - k) for k,m in zip(K, M)]
  all_K = list(product(*candidate_K))
  res = []
  for K_ in all_K:
    res.append(CRT(list(K_), M) % p)
  return res

K = [266, 307, 24, 378, 254, 106, 2231, 1473, 2700, 127, 743, 121, 2846, 898, 2734, 3350, 2668, 2611, 14559]
M = [643, 823, 919, 977, 1013, 1019, 4507, 5039, 5479, 5689, 5839, 6143, 6451, 12503, 12611, 17137, 20789, 29759, 62633]
candidates = generate_candidates(K, M)
print('\n'.join(map(str, candidates)))
```

Finally, we adapted some of the provided Go code to perform decryption and find the flag:

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"strings"

	"golang.org/x/crypto/hkdf"
)

func DeriveKey(secret, info []byte) ([]byte, error) {
	hash := sha256.New
	hkdf := hkdf.New(hash, secret, nil, info)

	key := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func main() {
	channelCipherKdfInfo := []byte("Flag Cipher v1.0")
	c_data := []byte(">}\"B\352\"WgA\234*\014p\326b\\O6\374\250\217K\343\334U\374\252~\267\026\325\212J\3178M\354{q\231\201\310\351yyj`3_\224^\313\204P\200\323\233=")
	c_iv := []byte("s@v\325g\340\t*\274\341\t\025\202UC}")
	dat, _ := ioutil.ReadFile("./candidate_keys")
	lines := strings.Split(string(dat), "\n")
	for _, line := range lines {
		secret := make([]byte, 28)
		D := new(big.Int)
		D.SetString(line, 10)
		D.FillBytes(secret)
		key, _ := DeriveKey(secret, channelCipherKdfInfo)
		aes_cipher, _ := aes.NewCipher(key)
		stream := cipher.NewCTR(aes_cipher, c_iv)
		plaintext := make([]byte, len(c_data))
		stream.XORKeyStream(plaintext, c_data)
		if string(plaintext)[:3] == "CTF" {
			fmt.Println(string(plaintext))
		}
	}
}
```

Flag: `CTF{ChocolateDoesNotAskSillyQuestionsChocolateUnderstands}`

---

# Pythia <a name="pythia"></a>

> Yet another oracle, but the queries are costly and limited so be frugal with them.
> 
> [attachment](https://storage.googleapis.com/gctf-2021-attachments-project/4fa9877430b27038d3fc863fd396cdce50fe32fca06c25c13743f642c584d2941449191fd70192c3fed8065abe4585006a08b8a7f9695450e7de99472633ddd6) `pythia.2021.ctfcompetition.com 1337`

Upon connection, the server generates three random passwords, each consisting of exactly three lowercase letters. We are presented a menu where we can:

1. `Set key`: Choose one of the three passwords for the server to use for the `Decrypt text` option
2. `Read flag`: Prints the flag if we provide the three passwords
3. `Decrypt text`: Uses a kdf to derive an AES key to decrypt and verify a given AESGCM nonce and ciphertext

We are allowed to make 150 queries, and there is a 10 second delay between each one. To get the flag, we must recover all three passwords.

An attack against this system is described [here](https://eprint.iacr.org/2020/1491.pdf). The `Decrypt text` option acts as a partitioning oracle. We are able to compute valid AESGCM ciphertexts and tags that decrypt and verify under multiple keys. If we ask the oracle to attempt to decrypt and verify a ciphertext and tag that is valid under half of the possible key set, then we will have effectively halved the number of keys to consider. We can repeat this in a recursive manner to find the correct key in time logarithmic in the number of possible keys.

## Attack Details

All operations are done in $\mathbb{F}_{2^{128}}$. For simplicity, we assume there is no additional data. The key idea is that, for any AES key $K$, ciphertext $C_1, \ldots, C_{k-1}$, nonce $N$ and tag $T$ the following relation holds:

$$
T = C_1 \cdot H^{k-1} + \cdots + C_{k-1} \cdot H^2 +L \cdot H + E_{K}(N || 0^{31} 1)
$$

where $L$ encodes the length of the ciphertext, and $H = E_K(0^{128})$.

We want to find a ciphertext $C_1, \ldots, C_k$ such that it decrypts and verifies under the set of keys $K_1, \ldots, K_k$. We can fix $T$ and $N$. Then, we have

$$
C_k + C_{k-1} \cdot H_i + \cdots + C_1 \cdot H_i^{k-1} = (L \cdot H_i + E_{K_i}(N||0^{31}1) + T) \cdot H_i^{-2}
$$

where again $L$ encodes the length of the ciphertext, and $H_i = E_{K_i}(0^{128})$.

Noting that the left hand side of this is a degree $k-1$ polynomial in $H$ with coefficients $C_k, \ldots, C_1$, we can use polynomial interpolation techniques to recover the $C_k, \ldots, C_1$ given $k$ points (i.e. $k$ different keys).

## Implementation

There are $26^3 = 17576$ different possible passwords for each of the three passwords. Ideally, this would mean we can recover each password using around $\log_2(26^3) \approx 14$ queries. However, this would require computing a ciphertext that decrypts and verifies under $17576/2 = 8788$ different keys. My implementation was able to compute ciphertexts that decrypt under $1024$ keys in around 2 minutes, and $512$ keys in around 20 seconds. Because the server gives us 150 queries, this is all we need to solve it within the constraints. There are $17576/1024 \approx 17$ "chunks" of 1024 keys, and once we determine which chunk the password belongs in, we can perform the recursive binary search to find the correct password in just 10 more queries. This means we will require at most 81 queries.

To save time, we precomputed the $1024$ chunks and $512$ chunks and computed the rest on the fly.

```py
import os, time
os.environ['PWNLIB_NOTERM'] = 'True'
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from string import ascii_lowercase
from itertools import product
from base64 import b64encode
from pwn import remote, process, context
from tqdm import tqdm

ORDERED_PASSWORDS = []
POSSIBLE_KEYS = {}
for a,b,c in product(ascii_lowercase, repeat=3):
    kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
    key = kdf.derive(bytes(a+b+c, 'UTF-8'))
    ORDERED_PASSWORDS.append(a+b+c)
    POSSIBLE_KEYS[a+b+c] = key

NONCE = b'\x55'*12
TAG = b'\x66'*16
F2.<x> = GF(2)[]
p = x^128 + x^7  + x^2 + x + 1
F = GF(2^128, 'x', modulus=p, impl='pari_ffelt')
R.<z> = PolynomialRing(F)

def block_aes(block, key):
    return AES.new(key, AES.MODE_CBC, iv=b'\x00'*16).encrypt(block)

# https://github.com/kste/keycommitment/blob/main/util.sage
def bytes_to_F(block):
    field_element = 0
    for i in range(128):
        if (block[i // 8] >> (7 - (i % 8))) & 1 == 1:
            field_element += x^i
    return F(field_element)

def F_to_bytes(element):
    coeff = element.polynomial().coefficients(sparse=False)
    result = [0 for _ in range(16)]
    for i in range(len(coeff)):
        if coeff[i] == 1:
            result[i // 8] |= (1 << ((7 - i) % 8))
    return bytes(result)

def attack(keys, nonce, tag):
    L = bytes_to_F(b'\x00' * 8 + long_to_bytes(128 * len(keys), 8))
    N = nonce + b'\x00'*3 + b'\x01'
    T = bytes_to_F(tag)
    interpolation_pts = []
    for key in keys:
        H = bytes_to_F(block_aes(b'\x00'*16, key))
        B = ((L * H) + bytes_to_F(block_aes(N, key)) + T) * H^-2
        interpolation_pts.append((H, B))
    start = time.time()
    sol = R.lagrange_polynomial(interpolation_pts)
    t = time.time() - start
    print(f'polynomial interpolation took {t}s')
    C_blocks = [F_to_bytes(c) for c in sol.coefficients(sparse=False)[::-1]]
    return b''.join(C_blocks)

def get_ciphertexts(CHUNK_SIZE, outdir):
    key_chunks = [ORDERED_PASSWORDS[i:i+CHUNK_SIZE] for i in range(0, len(ORDERED_PASSWORDS), CHUNK_SIZE)]
    s = sum(len(kc) for kc in key_chunks)
    if s < 26^3:
        key_chunks += [ORDERED_PASSWORDS[s:]]

    i = 0
    for keys in key_chunks:
        keys = [POSSIBLE_KEYS[pw] for pw in keys]
        import hashlib
        C = attack(keys, NONCE, TAG)
        print('C: ',hashlib.md5(C).hexdigest())
        l = str(i).zfill(5)
        open(f'{outdir}/{l}.dat', 'wb').write(C)
        i += len(keys)

        # sanity check; shouldn't throw an error
        aes = AES.new(keys[0], AES.MODE_GCM, nonce=NONCE)
        aes.decrypt_and_verify(C, TAG)

def oracle_decrypt(C):
    conn.sendlineafter('>>> ', '3')
    payload = b64encode(NONCE) + b',' + b64encode(C + TAG)
    conn.sendlineafter('>>> ', payload)
    conn.recvline()
    res = conn.recvline().decode()
    return 'success' in res

def solve_pw_rec(r):
    if r[1] - r[0] <= 1:
        return list(ORDERED_PASSWORDS)[r[0]]
    r1 = (r[0], (r[1]+r[0])//2)
    r2 = ((r[1]+r[0])//2, r[1])
    OP = ORDERED_PASSWORDS[r1[0]:r1[1]]
    PK = [POSSIBLE_KEYS[pw] for pw in OP]
    C = attack(PK, NONCE, TAG)
    if oracle_decrypt(C):
        return solve_pw_rec(r1)
    else:
        return solve_pw_rec(r2)

def solve_pw(idx, C1024, C512):
    conn.sendlineafter('>>> ', '1')
    conn.sendlineafter('>>> ', str(idx))

    # linear step through C1024
    LC1024 = list(C1024)
    for r in LC1024[:-1]:
        if oracle_decrypt(C1024[r]):
            break
    else:
        r = LC1024[-1]

    possible_C = {}
    for s in C512:
        if s[0] >= r[0] and s[1] <= r[1]:
            possible_C[s] = C512[s]
    assert len(possible_C) == 2
    r1, r2 = possible_C
    if oracle_decrypt(possible_C[r1]):
        return solve_pw_rec(r1)
    else:
        return solve_pw_rec(r2)

# get_ciphertexts(512, 'C512')
# get_ciphertexts(1024, 'C1024')

C1024 = {}
for f in os.listdir('./C1024'):
    l = int(f.strip('.dat'))
    r = (l, min(26^3, l + 1024))
    dat = open(f'./C1024/{f}', 'rb').read()
    C1024[r] = dat

C512 = {}
for f in os.listdir('./C512'):
    l = int(f.strip('.dat'))
    r = (l, min(26^3, l + 512))
    dat = open(f'./C512/{f}', 'rb').read()
    C512[r] = dat

conn = remote('pythia.2021.ctfcompetition.com', 1337)
pw0 = solve_pw(0, C1024, C512)
print('pw0 recovered:', pw0)
pw1 = solve_pw(1, C1024, C512)
print('pw1 recovered:', pw1)
pw2 = solve_pw(2, C1024, C512)
print('pw2 recovered:', pw2)
pw = pw0 + pw1 + pw2
print('password:', pw)
conn.sendlineafter('>>> ', '2')
conn.sendlineafter('>>> ', pw)
print(conn.recvline().decode())
print(conn.recvline().decode())
```

Flag: `CTF{gCm_1s_n0t_v3ry_r0bust_4nd_1_sh0uld_us3_s0m3th1ng_els3_h3r3}`

---

# Story <a name="story"></a>

> Please, tell me a beautiful story. 
> 
> [attachment](https://storage.googleapis.com/gctf-2021-attachments-project/95cc1cfc11276b5ea55d0668bb20019cdc965586051f9875bbca3aa555a832142c097031ed51243a486d1cb2d0f3f0bedc2b0b8178657d03688ced8aded6e2a7) `story.2021.ctfcompetition.com 1337`

The server asks us for a string of printable characters and computes some unknown CRC on it. It gives us the value of the CRC and then "randomises" our input in some way. The CRC and randomise functions are not given. It then gives us the randomised values and challenges us to provide a second input that consists of the same characters as the first input, only differing by capitalisation, which has a CRC value that is the same as the randomised values. We suspect that the randomise function simply flips the case (lowercase/uppercase) of characters in its input and computes the CRC of that.

The CRC function we are interested in produces CRCs of $112$ bits. When we tested against the server, we were able to pass the `expectedValues != null` check by providing strings of length `256`. So our approach will be to consider inputs of length `256` that consist of a single letter with different capitalisations in differnt positions. We will represent these as vectors of size `256` over $\mathbb{F}_2$, where a lowercase character is represented by $0$ and an uppercase character is represented by $1$. We also represent the CRC values as vectors of size `112` over $\mathbb{F}_2$, which we convert by simply looking at the binary string of the CRC value.

A known property of CRCs is that they are affine; a $\mathrm{CRC}$ that takes an $n$-bit input and produces an $m$-bit output can be represented by a matrix $M$ of size $m \times n$ and a vector $c_0$ where $c_0 = \mathrm{CRC}(0)$. Specifically, if $X$ is an $n$-bit input, then $\mathrm{CRC}(X) = MX + c_0$. We can write $M$ in terms of where the CRC maps the basis vectors of $\mathbb{F}_2^n$ (viewed as a vector space). So

$$
M =
\begin{pmatrix}
    | & | & & | \\
    c_1 & c_2 & \cdots & c_n \\
    | & | & & |
\end{pmatrix}
$$

where $c_i = \mathrm{CRC}([0, \ldots, 0, 1, 0, \ldots, 0])$ (the $1$ is in the $i$th position).

We can find the $c_i$ by asking the server for the CRC value of a `256` length string of `a`s where the $i$th character is capitalised.

Once we have $M$ and $c_0$, finding preimages, $X$, for a given target CRC, $T$, is easy:

$$
\begin{aligned}
    T &= MX + c_0 \\
    \implies MX &= T + c_0
\end{aligned}
$$

We simply need to solve the system of linear equations and any solution will pass the check.

```py
import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import *
from tqdm import tqdm

def get_corpus(N):
    corpus = {}
    S = b'a'*256
    for i in tqdm(range(N)):
        conn = remote('story.2021.ctfcompetition.com', 1337, level='error')
        conn.recvline()
        conn.recvline()
        conn.sendline(S)
        o = conn.recvline().decode()
        crc16, crc32, crc64 = [int(x, 16) for x in o.split('[')[1].strip('].\n').split(', ')]
        corpus[S] = (crc16, crc32, crc64)
        conn.close()
        S = b'a'*i + b'A' + b'a'*(255-i)
    return corpus

corpus = get_corpus(257)

def bytes_to_Fvec(b):
    return vector(F, [bool(c == 97) for c in b])

def num_to_Fvec(n, nbits):
    return vector(F, map(int, bin(n)[2:].zfill(nbits)))

def crc_to_vec(crc):
    return num_to_Fvec(crc[0] | crc[1] << 16 | crc[2] << 48, 112)

F = GF(2)
c0 = crc_to_vec(corpus[b'a'*256])
eqs = [crc_to_vec(corpus[s]) for s in list(corpus)[1:]]
M = Matrix(F, eqs).transpose()

conn = remote('story.2021.ctfcompetition.com', 1337)
conn.recvline()
conn.recvline()
conn.sendline('a'*256)
conn.recvline()
o = conn.recvline().decode()
target_crcs = [int(x, 16) for x in o.split('[')[1].strip('].\n').split(', ')]
target = crc_to_vec(target_crcs)
sol = M.solve_right(target + c0)
sol = ''.join(['aA'[i] for i in sol])
conn.sendline(sol)
print(conn.recvline().decode())
```

Flag: `CTF{eb64749d08bd99b681f2bc75aa65eab35a80310f7426f6872ba869d244e37135}`

---

# Tonality <a name="tonality"></a>

> In this challenge, you have access to a signing oracle.
>
> Good luck!
> [attachment](https://storage.googleapis.com/gctf-2021-attachments-project/00e0b30775a0702f807527555f02bd7f04dca5e88f1592d0a0f5a8dd9f81ea824efa69baf1a1ffa2ce3d736b260e3c7dd13483b1f4ff3da0fb6cef1455e43441) `tonality.2021.ctfcompetition.com 1337`

We have a similar setup to <a href="#tiramisu">Tiramisu</a>; we are given the Go code running on the server and a client to interact with it. The goal of this task is to forge an ECDSA signature given the ability to "scale" the server's private key for one signing. Specifically, when a client connects to the server, the server generates a private key and sends the client its public key. The server asks the client for a scalar and then signs a message, scaling its private key by the client-provided scalar. It then challenges the client to forge a signature for another message.

The server uses `secp256r1` so there are no insecure curve attacks. Let $d$ be the server's private key and let $h_1, h_2$ be the two messages. The server will sign $h_1$, and our goal is to sign $h_2$. Let $t$ be the scalar we provide to the server to scale its private key when it signs the the first message. The server generates a random nonce $k$ and computes $r_1 = (kG)_x$ and $s_1 = k^{-1}(h_1 + t r_1 d)$. We can control $t$, so set $t = \frac{h_1}{h_2}$. Then,

$$
\begin{aligned}
    s_1 &= k^{-1}(h_1 + t r_1 d) \\
        &= t k^{-1}\left (\frac{h_1}{t} + r_1 d \right ) \\
        &= \frac{h_1 k^{-1}}{h_2} \left (h_2 + r_1 d \right )
\end{aligned}
$$

Now, let

$$
\begin{aligned}
    s_2 &= t^{-1} s_1 \\
        &= \frac{h_2}{h_1}\frac{h_1 k^{-1}}{h_2} \left (  h_2 + r_1 d \right ) \\
        &= k^{-1} (h_2 + r_1 d)
\end{aligned}
$$

So $(r_1, s_2)$ is a valid signature for $h_2$.

```py
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha1
from client import init, get_first_signature, send_second_signature

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(GF(p), [a, b])
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

h1 = bytes_to_long(sha1(b'Server says 1+1=2').digest())
h2 = bytes_to_long(sha1(b'Server says 1+1=3').digest())
t = h1*inverse_mod(h2, n) % n

tube = init()
r1, s1 = get_first_signature(tube, t)
s2 = h2*inverse_mod(h1, n)*s1 % n
send_second_signature(tube, r1, s2) # this prints the flag
```

Flag: `CTF{TheySayTheEmptyCanRattlesTheMost}`

---

# H1 <a name="h1"></a>

> Crypto is not real hacking, they say.
> 
> [attachment](https://storage.googleapis.com/gctf-2021-attachments-project/bdf5ad72540eb6470b9161749a2cd39f426dd5500b02627329cc0157923267ef54ff39d4f6a81a5734f4c4297962f9df39eac3b0b62431b26b58b09df71204ae)

The handout script seems to implement some complicated addition and multiply functions. It turns out this is just an elliptic curve but using Jacobian coordinates. We can verify the addition and multiplication formulae with [this](http://koclab.cs.ucsb.edu/teaching/ecc/eccPapers/DocheLange-ch13.pdf) which also describes a mapping between the Jacobian coordinates and affine points. However, this is mostly a distraction from the actual challenge, as it is not really needed to solve.

We are given the transcript of an interaction between Alice and Bob who exchange two messages each, along with ECDSA signatures. The nonces for the ECDSA signatures are generated using a bespoke RNG. There are famous attacks against ECDSA that exploit weak nonce generation; when there is not enough entropy in the nonce, the secret key may be recovered. This is the case for this challenge.

The RNG used to generate the nonces in the challenge produce $512$-bit integers of the form

$$
a \sum_{i=0}^{64} (b_i 2^{32i}) = a (b_0 + b_1 2^{32} + \cdots + b_{15} 2^{32 \cdot 15})
$$

where the $b_i$ are each $8$ bits and $a = 2^{24} + 2^{16} + 2^8 + 1$ is a fixed constant.

We have two known messages and signatures from Bob to Alice, so we will use those. Call them $h_i, r_i, s_i$ for $i = 1, 2$. Suppose that $i$th first signature was signed using nonce $k_i = a \sum_{j=0}^{64}(b_{i,j}2^{32j})$. Then, from the ECDSA signature, we have

$$
s_i k_i = h_i + r_i d_B \implies s_i a \sum_{j=0}^{64}(b_{i,j}2^{32j}) - h_i - r_i d_B = 0
$$

Let $f_i = s_i a \sum_{j=0}^{64}(b_{i,j} 2^{32j}) - h_i - r_i d_B$. This is a polynomial in the 17 unknowns $b_{i,j}$, $0 \leq j < 16$ and $d_B$. We can combine $f_1$ and $f_2$ to eliminate $d_B$ to get a single polynomial $f_3$ in the 32 unknowns $b_{i,j}$ for $i = 1, 2$ and $0 \leq j < 16$.

Now, the key thing to notice is that the $b_{i,j}$ are small. In fact, the total number of unknown bits in $f_3$ is $32 \times 8 = 256$. Since we work over $\mathbb{F}_n$ where $n \approx 2^{512}$ is the order of the curve, we are be able to solve this knapsack-like problem using lattice techniques. Write

$$
f_3 = c_0 + c_1 b_{0,0} + c_2 b_{0,1}  + \cdots + c_{32} b_{2, 15}
$$

then consider the lattice generated by the rows of the matrix

$$
M =
\begin{bmatrix}
c_1 & 1 & 0 & \cdots & & 0\\
c_2 & 0 & 1 & & & \vdots \\
\vdots & & & \ddots \\
c_{32} & 0 & \cdots & & 1 & \\
c_{0} & 0 & \cdots & & & 1 \\
n & 0 & \cdots & & & 0
\end{bmatrix}
$$

The lattice will contain the short vector $(0, b_{0,0}, b_{0,1}, \ldots, b_{2,15}, 1)$ which we can find using LLL.

Once we have the nonce $k_1$, we can easily recover $d_B$ as

$$
d_B = \frac{s_1 k_1 - h_1}{r_1}
$$

The last thing is to recover Alice's public key, since it isn't given. Fortunately, it is possible to recover the possible public keys from a single signature. Suppose $(r, s)$ is a signature for the message $h$ signed with private key $d$ and nonce $k$. Let $R = kG$. We want to recover the public key $Q$. From the signature verification check, we have

$$
\begin{aligned}
    (hs^{-1})G + (rs^{-1})Q &= R \\
    \implies (rs^{-1})Q &= R - (hs^{-1})G \\
    \implies Q &= (r^{-1}s)R - (hr^{-1})G \\
    \implies Q &= r^{-1}(sR - hG) \\
\end{aligned}
$$

Noting that we only have the $x$-coordinate of $R$, we get two possible candidates for $R$ (for the $\pm y$). We simply try both to see which one decrypts the flag properly.

```py
import hashlib
from itertools import product
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Util.number import long_to_bytes, bytes_to_long

from sage.matrix.matrix2 import Matrix
def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))

def Decrypt(ciphertext, x):
    key = hashlib.sha256(str(x).encode()).digest()
    aes = algorithms.AES(key)
    decryptor = Cipher(aes, modes.ECB(), default_backend()).decryptor()
    unpadder = padding.PKCS7(aes.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize() 
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext 

A_r1, A_s1_ = ...
A_h1 = bytes_to_long(hashlib.sha512(b'Hello Bob.').digest())
A_r2, A_s2, flag_ct = ...
r1, s1, _ = 
h1 = bytes_to_long(hashlib.sha512(b'Hello Alice.').digest())
r2, s2, _ = ...
h2 = bytes_to_long(hashlib.sha512(b'Dinner sounds good. Thanks for the flag.').digest())
p = ...
a = ...
b = ...
n = ...
G = (..., ..., ...) 

F = GF(p)
R.<x,y,z> = F[]
cubic = y^2 - x^3 - a*x*z^4 - b*z^6
f,g = WeierstrassForm(cubic, variables=[x,y,z])
phi = lambda x, y, z: E(F(x/z^2), F(y/z^3))
E = EllipticCurve(F, [f,g])
G = E(*phi(*G))

P = PolynomialRing(Zmod(n), [f'b{j}{i}' for j in range(2) for i in range(16)] + ['d'])
B, d = P.gens()[:32], P.gens()[-1]
a = 16843009
k1 = a * sum(B[i] * 2^(32*i) for i in range(16))
k2 = a * sum(B[i+16] * 2^(32*i) for i in range(16))
f1 = k1 * s1 - h1 - r1 * d
f2 = k2 * s2 - h2 - r2 * d
f3 = resultant(f1, f2, d)
M = matrix.column(ZZ, vector([int(c) for c, _ in f3]))
M = M.augment(matrix.identity(33))
M = M.stack(vector([n] + [0]*33))
M = M.dense_matrix()
M = M.LLL()
b_subs = { B[i]: abs(M[0][i+1]) for i in range(32) }
k1 = k1.subs(b_subs)
k2 = k2.subs(b_subs)
db = F((s1*k1 - h1)/r1)

Qa = inverse_mod(A_r1, n)*(A_s1 * -E.lift_x(A_r1) - A_h1 * G)
print(Qa)
kb = (int(db)*Qa).xy()[0]
print(Decrypt(long_to_bytes(flag_ct), kb).decode())
```

Flag: `CTF{But_in_real_life_devs_would_never_use_such_a_buggy_RNG_right?}`
