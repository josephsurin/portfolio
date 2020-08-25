---
path: /posts/2020-08-09-poseidonctf-2020-writeups
title: PoseidonCTF 2020 Writeups
date: 2020-08-09
tags: ctf,infosec,writeup,crypto
---

Writeups for kiona's crypto challs from PoseidonCTF 2020.

- crypto
    - [Triplet Bits Encryption](#triplet-bits-encryption)
    - [discrete log](#discrete-log)

---

# Triplet Bits Encryption <a name="triplet-bits-encryption"></a>

### crypto (100pts)

> I have to encrypt super secret information, so I used triplet bits.
>
> Is it really safe?
>
> Author : kiona

`problem.py`:

```python
#!/usr/bin/env python3

from hashlib import sha256
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Random import get_random_bytes
from flag import flag

def mixkeybit(keybit1, keybit2, keybit3):
    return int(keybit1 or (not(keybit2) and keybit3))

key1 = get_random_bytes(32)
key2 = get_random_bytes(32)
key3 = get_random_bytes(32)

wfile = open('output.txt', 'w')

for _ in range(256):
    flagbin = bin(bytes_to_long(flag))[2:]
    encbin = ""
    for i in range(len(flagbin)):
        key1 = sha256(key1).digest()
        key2 = sha256(key2).digest()
        key3 = sha256(key3).digest()
        keybit1 = int(bin(bytes_to_long(key1))[2:][-1])
        keybit2 = int(bin(bytes_to_long(key2))[2:][-1])
        keybit3 = int(bin(bytes_to_long(key3))[2:][-1])
        encbin += str(mixkeybit(keybit1, keybit2, keybit3) ^ int(flagbin[i]))
    wfile.write(encbin)
    wfile.write('\n')
wfile.close()
```

`output.txt`: <a href="./assets/output.txt">output.txt</a>

## Solution

The encryption algorithm encrypts bits of the flag one by one. It does this by XORing each flag bit with some value that is derived from three (basically random) bits. How the bits are combined is defined in the `mixkeybit` function:

```python
def mixkeybit(keybit1, keybit2, keybit3):
    return int(keybit1 or (not(keybit2) and keybit3))
```

We can describe this using a truth table:

| $k_1$ | $k_2$ | $k_3$ | $k_1 \lor (\lnot k_2 \land k3)$ |
| ---   | ---   | ---   | ---     |
| $0$   | $0$   | $0$   | $0$     |
| $0$   | $0$   | $1$   | $1$     |
| $0$   | $1$   | $0$   | $0$     |
| $0$   | $1$   | $1$   | $0$     |
| $1$   | $0$   | $0$   | $1$     |
| $1$   | $0$   | $1$   | $1$     |
| $1$   | $1$   | $0$   | $1$     |
| $1$   | $1$   | $1$   | $1$     |

Since the input bits are seemingly random, it becomes apparent that the XOR value will be $0$ less often than $1$. Thankfully, we're given 256 encryptions of the same message! This means we can determine each bit of the message and therefore recover the entire message.

We'll do this by analysing all 256 ciphertexts bit by bit. For each bit position in the message, let $b$ be the value that occurs the least across all 256 ciphertexts. Then, it is very very likely that this bit is the flag bit we are interested in.

**Solve script:**

```python
cts = open('./output.txt').read().splitlines()
Z = zip(*cts)
def least_freq(lst):
    return '1' if lst.count('0') > lst.count('1') else '0'
flag = ''.join(least_freq(B) for B in Z)
print(bytes.fromhex(hex(int(flag, 2))[2:]).decode())
```

Flag: `Poseidon{7h3_u53_0f_pr0b4b1l17y_15_57r0n6}`

---

# discrete log <a name="discrete-log"></a>

### crypto (908pts)

> I heard some cryptosystem uses discrete logarithm.
>
> It is hard problem, isn't it?
>
> I encrypted the flag with 4095bit modulus...
>
> Author : kiona

`problem.py`:

```python
#!/usr/bin/env python3

from Crypto.Util.number import isPrime, getPrime, getRandomRange, bytes_to_long
from flag import flag

def keygen():
    p = getPrime(1024)
    q = p**2 + (1<<256)
    while not(isPrime(q)):
        q += 2
    n = p**2 * q
    while True:
        g = getRandomRange(2, n-1)
        if pow(g, p-1, p**2) != 1:
            break
    return (g, n), p

def encrypt(pubkey, msg):
    g, n = pubkey
    msgint = bytes_to_long(msg)
    encint = pow(g, msgint, n)
    return encint

wfile = open('output.txt', 'w')

pubkey, privkey = keygen()

print(privkey)
wfile.write('g = ' + str(pubkey[0]) + '\n')
wfile.write('n = ' + str(pubkey[1]) + '\n')

encint = encrypt(pubkey, flag)
wfile.write('enc = ' + str(encint) + '\n')

wfile.close()
```

`output.txt`:

```
g = 172749132303451034825184289722866887646478207718904031630914096520683022158034517117605936723970812800902379716660696042889559048647206589145869496198395421965440272135852383965230458163451729744948637995163776071512309614027603968693250321092562108610034043037860044795655266224453184735452048413623769098671844195106558284409006269382544367448145088128499405797694142037310933061698125568790497068516077791616445318819525778890129259953967830407023305805724947609041398183006524760589480514375528363943261764527906775893795625189651746165941438248136930298545695110631212696683271254403308539994170329875688236599305478130030194371971383054083049610267982461416568688720562725217837462387935392946474596966349477680685726377666929540130924122398746591270899232208239961618302848348129375606841006687727574503519146164506867574157671109933022528435615415554171024171300585408907077259610240139419075684581512703943171162496513070572546968852202777002845137863414028314025114932581655385254082418111977242759980115915504202336380850329162861826132885827910210346708045087589916666711356848614195462267049823085141386868421005551877773672329046391854000523197388175515628464457551891476514779819019668102328395639607489673081022505099
n = 204964538005458094391574690738766104196067587947267165575341074475716043971842449550067337731195102944823593489101699510575531541895593939634478254160200896755891641047742120885540191258962212405226135805491196590351987106011483652123110409148411537235255207358696047015199616340882291357173918540392964501976492251077110794432722042202109934588262870543755493029748475008610896164870659893013085704495216717998116109896882952474884270785733861739050889113464275228554841649603978281963688294995328883256317404081735364738985601286409677647577052211093127231530844271726386293348738817021732679704754961436390654856963930636538653822714234978179695778198536592408645222590877027896792957778186555118729335564281356291031440583078132397563914801937048297147819254611598144027963328749607393168101280779708669908245620694587176737529113823312930871616550632035759346759393976128246210013752530912953330415598837661326422094379798718827988692760848583517436061574821754507293943235476923624688378441177770313101393581916112910947153305055575974237171438666919114843946573283829704010962833299593770650238349021406868347635157566404829030358844616367849771415905381318344903398551946493709551783771889575282972265629264217620138873678733
enc = 58749077215207190492371298843854826665007067693641554277597021927783439106518176607848876784025881251057880587477892585242567469682290542409002363284991521084199535617805983767364935247518813883871587009725229910084882524866335007624383374126379502610933045897762967063766174922757656816300993939273687091280630401460905159739072179134897626330594985795970230333335492872721173603390854317323095769925904629970032658376378937924244589208035572848434030889091930182042226202356340798415809817722086119981262671540923062830870681500341640178082497128371291359953884993700348396920219975667972939044100089402796215197615549948516999318565775626034391795498234335228509335613253342179818268681240653806015040771731154600343889814141382273506238199460016081871283682838719833841393528105371834961952754168257271394981634141286257602629174903644009990944563870674888760807045240859970974837258567236802649772719645362361127488126570702845624169598462415354350277654287009645871674305081755840523910495569765451437265785385267255452210836618705384598344351666486694835670072372776263570462639412759703397195350879217144135006968472391258993407007505079063659488976186871280542665310586453539153772026697145449262179967269376262891840972187
```

## Solution

This was actually a very easy challenge, but it had quite few solves probably because the cryptosystem being used isn't known very well(?). The cryptosystem being used is the [Okamoto-Uchiyama cryptosystem](https://en.wikipedia.org/wiki/Okamoto%E2%80%93Uchiyama_cryptosystem). Its security is based on the integer factorisation problem.

In short, this is how the cryptosystem works (as was in the challenge):

### Key generation

Suppose Bob wants to send Alice a message. Alice generates two large primes $p$ and $q$ and computes $n = p^2 q$. She then chooses a random integer $2 \leq g < n$ such that $g^{p-1} \not\equiv 1 \pmod {p^2}$. Her public key is $(n, g)$ and her private key is the factorisation of $n$.

### Encryption

Bob encrypts a message $m < p$ by computing $c = g^m \mod n$ using Alice's public key. He sends $c$ to Alice.

### Decryption

Alice decrypts Bob's encrypted message by computing

$$\begin{aligned} a &= \frac{(c^{p-1} \mod {p^2}) - 1}{p} \\ b &= \frac{(g^{p-1} \mod {p^2}) - 1}{p} \end{aligned}$$

and then computing

$$m \equiv ab^{-1} \pmod p$$

Note: The actual cryptosystem introduces randomness by adding another parameter $h \equiv g^n \pmod n$ to the public key, and encrypting by computing $c \equiv g^m h^r \pmod n$ for a random $r$.

### Solving the challenge

It turns out the factorisation problem is easy in this situation because $q$ is generated from $p$, and we can write a quartic in $p$ with known coefficients. Specifically, $q$ is the next prime after $p^2 + 2^{256}$. Prime gaps are quite small, so we can write $q = p^2 + 2^{256} + \delta$ for some brute-forcable $\delta$. Then

$$\begin{aligned} n &= p^2 q \\ &= p^2 (p^2 + 2^{256} + \delta) \end{aligned}$$

After we recover the prime factorisation of $n$, we can decrypt as described above. 

**Solve script:**

```python
n = 204964538005458094391574690738766104196067587947267165575341074475716043971842449550067337731195102944823593489101699510575531541895593939634478254160200896755891641047742120885540191258962212405226135805491196590351987106011483652123110409148411537235255207358696047015199616340882291357173918540392964501976492251077110794432722042202109934588262870543755493029748475008610896164870659893013085704495216717998116109896882952474884270785733861739050889113464275228554841649603978281963688294995328883256317404081735364738985601286409677647577052211093127231530844271726386293348738817021732679704754961436390654856963930636538653822714234978179695778198536592408645222590877027896792957778186555118729335564281356291031440583078132397563914801937048297147819254611598144027963328749607393168101280779708669908245620694587176737529113823312930871616550632035759346759393976128246210013752530912953330415598837661326422094379798718827988692760848583517436061574821754507293943235476923624688378441177770313101393581916112910947153305055575974237171438666919114843946573283829704010962833299593770650238349021406868347635157566404829030358844616367849771415905381318344903398551946493709551783771889575282972265629264217620138873678733
g = 172749132303451034825184289722866887646478207718904031630914096520683022158034517117605936723970812800902379716660696042889559048647206589145869496198395421965440272135852383965230458163451729744948637995163776071512309614027603968693250321092562108610034043037860044795655266224453184735452048413623769098671844195106558284409006269382544367448145088128499405797694142037310933061698125568790497068516077791616445318819525778890129259953967830407023305805724947609041398183006524760589480514375528363943261764527906775893795625189651746165941438248136930298545695110631212696683271254403308539994170329875688236599305478130030194371971383054083049610267982461416568688720562725217837462387935392946474596966349477680685726377666929540130924122398746591270899232208239961618302848348129375606841006687727574503519146164506867574157671109933022528435615415554171024171300585408907077259610240139419075684581512703943171162496513070572546968852202777002845137863414028314025114932581655385254082418111977242759980115915504202336380850329162861826132885827910210346708045087589916666711356848614195462267049823085141386868421005551877773672329046391854000523197388175515628464457551891476514779819019668102328395639607489673081022505099
enc = 58749077215207190492371298843854826665007067693641554277597021927783439106518176607848876784025881251057880587477892585242567469682290542409002363284991521084199535617805983767364935247518813883871587009725229910084882524866335007624383374126379502610933045897762967063766174922757656816300993939273687091280630401460905159739072179134897626330594985795970230333335492872721173603390854317323095769925904629970032658376378937924244589208035572848434030889091930182042226202356340798415809817722086119981262671540923062830870681500341640178082497128371291359953884993700348396920219975667972939044100089402796215197615549948516999318565775626034391795498234335228509335613253342179818268681240653806015040771731154600343889814141382273506238199460016081871283682838719833841393528105371834961952754168257271394981634141286257602629174903644009990944563870674888760807045240859970974837258567236802649772719645362361127488126570702845624169598462415354350277654287009645871674305081755840523910495569765451437265785385267255452210836618705384598344351666486694835670072372776263570462639412759703397195350879217144135006968472391258993407007505079063659488976186871280542665310586453539153772026697145449262179967269376262891840972187

F = IntegerModRing(n)
g = F(g)
enc = F(enc)

R.<x> = ZZ[]
for delta in range(0, 10000, 2):
    poly = (x^2) * (x^2 + (1<<256) + delta) - n
    roots = poly.factor()
    for r,_ in roots:
        p = r[0] 
        if p.is_prime():
            break
    if p.is_prime():
        break

print('[+] found p:', p)
q = n//(p**2)
print('[+] found q:', q)

c = enc
a = ZZ(pow(c, p-1, p**2) - 1)//p
b = ZZ(pow(g, p-1, p**2) - 1)//p
b_ = inverse_mod(b, p)
m = a*b_ % p

print(bytes.fromhex(hex(m)[2:]))
```

Flag: `Poseidon{l064r17hm_fr0m_7h3_cycl1c_6r0up}`