---
path: /posts/2021-01-31-justctf-2020-crypto-writeups
title: justCTF 2020 - Crypto
date: 2021-01-31
tags: ctf,infosec,writeup,crypto
---

Fun CTF but not enough crypto challs :(. I managed to get first blood on 25519!

# 25519

> One time signatures, so you can spend your coins only once.
>
> Please solve the task locally first and reach our server only for the flag :)
>
> `nc c25519.nc.jctf.pro 1337`

```py
#!/use/bin/env sage

from sys import exit
from hashlib import sha256


FLAG = open('./flag.txt').read()

ec = EllipticCurve(GF(2**255-19), [0, 486662, 0, 1, 0])
p = ec.order()
ZmodP = Zmod(p)
G = ec.lift_x(9)

ha = lambda x: x if isinstance(x, int) or isinstance(x, Integer) else product(x.xy())
hashs = lambda *x: int.from_bytes(sha256(b'.'.join([b'%X' % ha(x) for x in x])).digest(), 'little') % p


def hashp(x):
    x = hashs((x))
    while True:
        try:
            return ec.lift_x(x)
        except:
            x = hashs((x))


def keygen():
    x = randint(1, p-1)
    P = x * G
    return x, P


def verify(signature, P, m):
    I, e, s = signature
    return e == hashs(m, s*G + e*P, s*hashp(P) + e*I)


if __name__ == "__main__":
    x, P = keygen()
    m = randint(1, p-1)
    print(x, P, m)

    spent = set()
    for i in range(8):
        Ix = int(input('I (x): '))
        Iy = int(input('I (y): '))
        I = ec(Ix, Iy)
        e = int(input('e: '))
        s = int(input('s: '))
        if verify((I, e, s), P, m) and I not in spent:
            print('ok')
            spent.add(I)
        else:
            print('nope')
            exit(1)

    print(FLAG)
```

## Solution

The service implements some kind of signature scheme using Curve25519 (although I'm not sure that the curve is actually relevant to the challenge). The task is to create 8 signatures for unique points on the curve.

 Let's call `hashs` $H_S$ and `hashp` $H_P$. $H_S$ takes an arbitrary number of arguments which can be either integers or curve points and computes a hash from the inputs. $H_P$ computes a hash from a curve point.

In each round of the game, we provide three inputs to the server: a curve point $I = (I_x, I_y)$ and two integers $e$ and $s$. These inputs must satisfy the condition

$$
e = H_S(m, sG + eP, s H_P(P) + eI)
$$

where $G$ is the curve's base point, $m$ is a random number and $P = xG$ for some random $x$. We are given all of $x$, $m$ and $G$.

$e$ appears on both sides of the equation which can make things a bit confusing. The key thing to realise is that we have control over everything except for $m$. If we try to choose inputs such that the second and third arguments to $H_S$ are some fixed point (e.g. $cG$ for some $c$), then we can assume that we know what $e$ will be and work with that.

So let $c$ be some (random) number that we do not particularly care about. The goal will be to choose $s$ and $I$ such that

$$
sG + eP = s H_P(P) + eI = cG
$$

Then $e = H_S(m, cG, cG)$, which doesn't use either of $s$ or $I$, so we can assume knowledge of $e$ when figuring out what to send for $s$ and $I$.

We'll work our way towards expressions for $s$ and $I$ in terms of things we know. From the second argument, we get:

$$
\begin{aligned}
    sG + eP &= cG \\
    \implies sG &= cG - eP \\
    \implies sG &= (c - ex)G \\
    \implies s  &= c - ex
\end{aligned}
$$

From the third argument, we get:

$$
\begin{aligned}
    s H_P(P) + eI &= cG \\
    \implies eI &= cG - s H_P(P) \\
    \implies I &= e^{-1} (cG  - s H_P(P))
\end{aligned}
$$

Since we work in the ring of integers modulo the curve order, which is even, $e^{-1}$ won't exist if $e$ is even. We can just keep trying with different values of $c$ until we get one that works (which should happen about half of the time).

```py
from os import environ
environ['PWNLIB_NOTERM'] = 'True'
from pwn import remote
from hashlib import sha256

ha = lambda x: x if isinstance(x, int) or isinstance(x, Integer) else product(x.xy())
hashs = lambda *x: int.from_bytes(sha256(b'.'.join([b'%X' % ha(x) for x in x])).digest(), 'little') % p

def hashp(x):
    x = hashs((x))
    while True:
        try:
            return E.lift_x(x)
        except:
            x = hashs((x))

E = EllipticCurve(GF(2^255 - 19), [0, 486662, 0, 1, 0])
p = E.order()
ZmodP = Zmod(p)
G = E.lift_x(9)

conn = remote('c25519.nc.jctf.pro', 1337)
data = conn.recvline().decode().strip()
x = int(data.split()[0])
P = x*G
m = int(data.split()[-1])

wins = 0
while wins < 8:
    c = randint(1, p)
    e = hashs(m, c*G, c*G)
    if not e & 1: continue
    s = c - e*x
    I = inverse_mod(e, p)*(c*G - s*hashp(P))
    conn.sendlineafter('I (x): ', str(I.xy()[0]))
    conn.sendlineafter('I (y): ', str(I.xy()[1]))
    conn.sendlineafter('e: ', str(e))
    conn.sendlineafter('s: ', str(s))
    conn.recvline()
    wins += 1

print(conn.recvline().decode())
```

Flag: `jCTF{th1s_g4me_st0p_on1y_onc3}`

# Oracles

> Ask them and decrypt the flag.
>
> http://oracles.web.jctf.pro

Relevant JS source:

```js
var express = require('express');
var router = express.Router();
var asmCrypto = require('asmcrypto.js');
var b64 = require('base64url');
var fs = require('fs');

const key_params = fs.readFileSync('./oracles_stuff/key').toString().split(/\r?\n/);

// ...

const oraclePythia = new asmCrypto.RSA_OAEP(pubKey, new asmCrypto.Sha256(), fs.readFileSync('./oracles_stuff/Pythia'));
const oracleDodona = new asmCrypto.RSA_OAEP(pubKey, new asmCrypto.Sha256(), fs.readFileSync('./oracles_stuff/Dodona'));
const oracleIthlinne = new asmCrypto.RSA_OAEP(pubKey, new asmCrypto.Sha256(), fs.readFileSync('./oracles_stuff/Ithlinne'));

const TheQuestion1 = oraclePythia.encrypt(fs.readFileSync('./oracles_stuff/Goldbach'));
const TheQuestion2 = oracleDodona.encrypt(fs.readFileSync('./oracles_stuff/UltimateQuestion'));
const TheQuestion3 = oracleIthlinne.encrypt(fs.readFileSync('./oracles_stuff/flag'));

router.get('/', function(req, res, next) {
  res.render('index', {
    qP:b64.encode(TheQuestion1),
    qD:b64.encode(TheQuestion2),
    qI:b64.encode(TheQuestion3)
  });
});

router.get('/ask', function(req, res, next) {
  var oracleName = req.query.oracleName || 'Pythia';

  var question = req.query.question;
  if (question == undefined || question.length < 4) {
    res.render('index', {response: 'No question asked.'});
    return;
  }
  question = new Uint8Array(b64.toBuffer(question));

  const oracle = new asmCrypto.RSA_OAEP(privkey, new asmCrypto.Sha256(), fs.readFileSync('./oracles_stuff/' + oracleName));

  var response = 'I won\'t answer.';
  try {
      const result = oracle.decrypt(question);
      asmCrypto.bytes_to_string(result);
  } catch(err) {
      //
  }

  res.render('index', {response: response});
});
```

## Solution

In this challenge, we have access to an RSA OAEP decryption oracle, except we don't actually get given the decryption result! The fact that the decryption operation is present in the code however hints at a timing attack. Searching for keywords like "RSA OAEP decryption oracle attack" gives [Manger's attack](https://www.iacr.org/archive/crypto2001/21390229.pdf) and fortunately [there already exists an implementation](https://www.iacr.org/archive/crypto2001/21390229.pdf)! This attack recovers the plaintext for a given ciphertext in about 1100 oracle queries for a 1024-bit RSA key.

The attack works by having the oracle answer queries of the form "is $y \equiv x^d \pmod n$ less than $B$" for specifically chosen $x$, and $B$ depending on the size of $n$. Read the paper for full details; it explains it quite well and even includes some notes about using timings to distinguish (section 4.4). In particular, it explains that an attacker which has some control over the label parameter can use this to easily distinguish ciphertexts in some implementations where errors are thrown early for "bad" ciphertexts. Taking a look at the asmcrypto.js [source](https://github.com/asmcrypto/asmcrypto.js/blob/2a7a339aea5a00c023479df6cb84acec8eb7373f/src/rsa/pkcs1.ts#L76), we see that this is exactly the case:

```js
    this.rsa.decrypt(new BigNumber(data));

    const z = this.rsa.result[0];
    const seed = this.rsa.result.subarray(1, hash_size + 1);
    const data_block = this.rsa.result.subarray(hash_size + 1);

    if (z !== 0) throw new SecurityError('decryption failed');

    const seed_mask = this.RSA_MGF1_generate(data_block, seed.length);
    for (let i = 0; i < seed.length; i++) seed[i] ^= seed_mask[i];

    const data_block_mask = this.RSA_MGF1_generate(seed, data_block.length);
    for (let i = 0; i < data_block.length; i++) data_block[i] ^= data_block_mask[i];

    const lhash = this.hash
      .reset()
      .process(this.label || new Uint8Array(0))
      .finish().result as Uint8Array;
    for (let i = 0; i < hash_size; i++) {
      if (lhash[i] !== data_block[i]) throw new SecurityError('decryption failed');
    }
```

This line

```js
    if (z !== 0) throw new SecurityError('decryption failed');
```

will cause the decryption process to stop early, which is indicative of the condition $x^d \mod n \geq B$. Otherwise, if the check is passed, a hash is computed over the label. To make this timing difference as noticeable as possible, we want to use a large label. In the challenge source,

```js
  const oracle = new asmCrypto.RSA_OAEP(privkey, new asmCrypto.Sha256(), fs.readFileSync('./oracles_stuff/' + oracleName));
```

we see that the label parameter is vulnerable to a path traversal bug. We found that using the `../../../../../usr/local/bin/node` binary (about 40MB) gave good results.

There isn't much to solving the challenge other than that. Here's the exploit script that uses a very slightly modified version of the existing Manger attack [implementation](https://github.com/kudelskisecurity/go-manger-attack) (changed the oracle interface to use just one `Query` function, and included the label from the challenge in the decryption part of the attack). For some reason, the exploit isn't 100% reliable and for some ciphertexts, is only able to accurately recover half of the bits of the padded plaintext. Luckily my teammate spun up a DO droplet in the same datacenter as the server and the exploit ran relatively quickly, so we just kept running it and eventually the flag popped out.

```go
package main
import (
	"encoding/hex"
	"fmt"
	"net/http"
	"math/big"
	"time"
	"github.com/dvsekhvalnov/jose2go/base64url"

	. "exploit/mangerattack"
)

func get_time(url string) int64 {
    start := time.Now()
    resp, _ := http.Get(url)
    defer resp.Body.Close()
	t := time.Since(start)
    fmt.Println(t, t.Microseconds(), url)
	return t.Microseconds()
}

type Oracle struct {}

func (Oracle) Query(mcfe *big.Int) bool {
	url := "http://localhost:3000/ask?oracleName=../../../../../usr/local/bin/node&question="
	b := mcfe.Bytes()
	t := get_time(url + base64url.Encode(b))
	// short decryptions take around 20-50ms on average
	// long decryptions take 300ms+
	return t < 200000
}

func main() {
	// local values for testing
	N := FromBase16("B9081FCBE46C2E844C671311FD15A08C551EA4E66E193CC81D954421CE96E99D41A9FE84A6FBAB898EBF4FE5D0E2EFE578CFF643DDB77480137B09A88B6A95130E5E5D81451C85C3BEFE28E2284D0C20961238B1354B43C487ECB9C4570E6DE820CAB99F92FC44C7C661FD64F13B5A067F46B0A8617445161DCAF896B0E18F75")
	e := big.NewInt(int64(0x10001))
	ct_raw, _ := base64url.Decode("glgKGkawHLTOs5KjYaFSBMN1Q0r1XktCZXwZLXGCt6XTXnMsHbhdKH-rdl1gQcl7bAm0wOVL2Jz5fwMlfZBySiJ4fU1WQ79PZ391f10f_QiCpX6syglITxFfKNv_CJIEufaql-WjWTSJrulzYEVEUDFwuX1AixiTi0fchuLUVQ4")
	ct_hex := hex.EncodeToString(ct_raw)

	MangerAttack(ct_hex, N, e, Oracle{})
}
```

Flag: `justCTF{60c173b4c6554af11e43a8c95190dcde749443}`
