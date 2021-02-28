---
path: /posts/2021-02-28-aero-ctf-2021-phoenix
title: Aero CTF 2021 - phoenix
date: 2021-02-28
tags: ctf,infosec,writeup,crypto
---

# phoenix

> If you want to become a member of the Order of the Phoenix, you need to:
>
>   be able to perfectly control the magic wand
>   be able to crack the following cipher
>
> ...but maybe some of this is not needed 

```py
#!/usr/bin/env sage

p = 2
F = GF(p)
P.<x> = PolynomialRing(F)


class Cipher:
    def __init__(self, size, params):
        self.size = size
        self.params = params

    def sequence(self, key):
        while True:
            key = key * self.params[0]
            yield key + self.params[1]

    def encrypt(self, key, data, strength):
        for value, pbit in zip(self.sequence(key), data):
            xbit = sum(value[i] for i in range(0, strength, 2))
            ybit = mul(value[i] for i in range(1, strength, 2))
            
            yield int(pbit) ^^ int(xbit) ^^ int(ybit)


def main():
    size = 256
    length = 1024
    strength = 10

    q = P.irreducible_element(size, 'minimal_weight')
    R.<x> = P.quo(q)

    key, a, b = [R.random_element() for _ in range(3)]

    with open('flag.txt', 'rb') as file:
        flag = file.read().strip()

    message = int.from_bytes(flag, 'big')
    assert message.bit_length() < size
    plaintext = list(map(int, bin(message)[2:]))
    padding = [0] * (length - len(plaintext))

    cipher = Cipher(size, [a, b])
    ciphertext = list(cipher.encrypt(key, padding + plaintext, strength))
    result = int(''.join(map(str, ciphertext)), 2)

    print(a)
    print(b)
    print(result)


if __name__ == '__main__':
    main()
```

```
x^255 + x^252 + x^246 + x^245 + x^240 + x^239 + x^236 + x^234 + x^233 + x^232 + x^231 + x^229 + x^228 + x^227 + x^224 + x^223 + x^218 + x^217 + x^216 + x^215 + x^210 + x^209 + x^204 + x^202 + x^200 + x^198 + x^197 + x^196 + x^192 + x^188 + x^187 + x^182 + x^181 + x^180 + x^178 + x^177 + x^176 + x^174 + x^173 + x^172 + x^167 + x^166 + x^161 + x^160 + x^157 + x^155 + x^154 + x^151 + x^150 + x^149 + x^148 + x^147 + x^146 + x^144 + x^140 + x^137 + x^135 + x^133 + x^132 + x^130 + x^129 + x^126 + x^122 + x^119 + x^118 + x^115 + x^112 + x^111 + x^109 + x^107 + x^106 + x^105 + x^104 + x^101 + x^100 + x^99 + x^97 + x^96 + x^94 + x^92 + x^87 + x^86 + x^84 + x^83 + x^81 + x^79 + x^75 + x^71 + x^69 + x^68 + x^67 + x^66 + x^65 + x^63 + x^62 + x^61 + x^56 + x^55 + x^53 + x^52 + x^50 + x^46 + x^44 + x^43 + x^41 + x^39 + x^38 + x^37 + x^36 + x^35 + x^34 + x^33 + x^32 + x^30 + x^29 + x^27 + x^24 + x^21 + x^17 + x^16 + x^14 + x^13 + x^12 + x^11 + x^10 + x^9 + x^5 + x^4 + x^3 + x + 1
x^255 + x^254 + x^250 + x^247 + x^243 + x^242 + x^241 + x^238 + x^235 + x^232 + x^229 + x^227 + x^222 + x^221 + x^219 + x^218 + x^217 + x^216 + x^215 + x^211 + x^207 + x^206 + x^204 + x^202 + x^201 + x^197 + x^195 + x^193 + x^192 + x^190 + x^189 + x^188 + x^186 + x^184 + x^181 + x^180 + x^179 + x^178 + x^176 + x^173 + x^172 + x^169 + x^167 + x^165 + x^161 + x^160 + x^158 + x^149 + x^147 + x^146 + x^145 + x^140 + x^138 + x^137 + x^134 + x^133 + x^132 + x^130 + x^129 + x^128 + x^126 + x^125 + x^124 + x^121 + x^120 + x^118 + x^117 + x^114 + x^112 + x^111 + x^110 + x^109 + x^108 + x^107 + x^106 + x^105 + x^101 + x^96 + x^95 + x^94 + x^93 + x^92 + x^90 + x^89 + x^88 + x^86 + x^85 + x^84 + x^83 + x^81 + x^80 + x^79 + x^78 + x^77 + x^76 + x^71 + x^70 + x^69 + x^68 + x^67 + x^64 + x^63 + x^59 + x^56 + x^55 + x^53 + x^50 + x^46 + x^43 + x^42 + x^40 + x^38 + x^37 + x^35 + x^34 + x^33 + x^25 + x^23 + x^22 + x^21 + x^18 + x^16 + x^14 + x^13 + x^12 + x^11 + x^10 + x^8 + x^3 + x^2 + x
69824286833704501471834043923417254326103912707315595840737453739249974863266259092449058810542265536810346421685955365128856715192808287450464619418781355923155781710833586631897182535937891456025282049302526058466298304955387306232279075295308862156912873485647349272079984781574084434511227361370780842056
```

## Solution

### Finite Fields of Prime Power Order

The key and the parameters to the cipher in the challenge are elements of the finite field $GF(2^{256})$. This field is constructed by taking the quotient ring $GF(2)[x]/(P)$ for some irreducible polynomial $P$ of degree 256. Elements of $GF(2^{256})$ can be thought of as polynomials with coefficients in $GF(2)$ reduced modulo $P$.

### Challenge Analysis

The flag is encrypted by XORing the bits of the flag with the outputs of a PRG. The PRG is given a secret key $k \in GF(2^{256})$ and public parameters $a, b \in GF(2^{256})$ and derives random bits from the terms of $ka^i + b$ with degree less than 10. Specifically, the `xbit` is the sum of the coefficients of the even degree terms, and the `ybit` is the product of the coefficients of the odd degree terms.

The flag is padded by 768 zero bits which gives us some information about the PRG output. Since the `ybit` is a product of 5 terms, it is going to be zero most of the time. This means, we can more or less assume that the PRG output is just `xbit`.

### Recovering the Key

Assuming we have 768 bits of the PRG output, how can we recover the key? The key thing to notice is that the values from the sequence are very linear. We can represent each `xbit` as a linear equation of the coefficients of the key. To do this, we represented the key symbolically and found expressions for each of the first 768 `xbit`s in terms of the key.

I'm sure there's a better way, but here's how we did it with Sage:

```py
P.<t> = PolynomialRing(GF(2))
Kr = PolynomialRing(GF(2), [f'k{i}' for i in range(256)])
q = P.irreducible_element(256, 'minimal_weight')
T.<y> = PolynomialRing(Kr)
R.<x> = T.quo(q)

a = x^255 + x^252 + x^246 + x^245 + x^240 + x^239 + x^236 + x^234 + x^233 + x^232 + x^231 + x^229 + x^228 + x^227 + x^224 + x^223 + x^218 + x^217 + x^216 + x^215 + x^210 + x^209 + x^204 + x^202 + x^200 + x^198 + x^197 + x^196 + x^192 + x^188 + x^187 + x^182 + x^181 + x^180 + x^178 + x^177 + x^176 + x^174 + x^173 + x^172 + x^167 + x^166 + x^161 + x^160 + x^157 + x^155 + x^154 + x^151 + x^150 + x^149 + x^148 + x^147 + x^146 + x^144 + x^140 + x^137 + x^135 + x^133 + x^132 + x^130 + x^129 + x^126 + x^122 + x^119 + x^118 + x^115 + x^112 + x^111 + x^109 + x^107 + x^106 + x^105 + x^104 + x^101 + x^100 + x^99 + x^97 + x^96 + x^94 + x^92 + x^87 + x^86 + x^84 + x^83 + x^81 + x^79 + x^75 + x^71 + x^69 + x^68 + x^67 + x^66 + x^65 + x^63 + x^62 + x^61 + x^56 + x^55 + x^53 + x^52 + x^50 + x^46 + x^44 + x^43 + x^41 + x^39 + x^38 + x^37 + x^36 + x^35 + x^34 + x^33 + x^32 + x^30 + x^29 + x^27 + x^24 + x^21 + x^17 + x^16 + x^14 + x^13 + x^12 + x^11 + x^10 + x^9 + x^5 + x^4 + x^3 + x + 1
b = x^255 + x^254 + x^250 + x^247 + x^243 + x^242 + x^241 + x^238 + x^235 + x^232 + x^229 + x^227 + x^222 + x^221 + x^219 + x^218 + x^217 + x^216 + x^215 + x^211 + x^207 + x^206 + x^204 + x^202 + x^201 + x^197 + x^195 + x^193 + x^192 + x^190 + x^189 + x^188 + x^186 + x^184 + x^181 + x^180 + x^179 + x^178 + x^176 + x^173 + x^172 + x^169 + x^167 + x^165 + x^161 + x^160 + x^158 + x^149 + x^147 + x^146 + x^145 + x^140 + x^138 + x^137 + x^134 + x^133 + x^132 + x^130 + x^129 + x^128 + x^126 + x^125 + x^124 + x^121 + x^120 + x^118 + x^117 + x^114 + x^112 + x^111 + x^110 + x^109 + x^108 + x^107 + x^106 + x^105 + x^101 + x^96 + x^95 + x^94 + x^93 + x^92 + x^90 + x^89 + x^88 + x^86 + x^85 + x^84 + x^83 + x^81 + x^80 + x^79 + x^78 + x^77 + x^76 + x^71 + x^70 + x^69 + x^68 + x^67 + x^64 + x^63 + x^59 + x^56 + x^55 + x^53 + x^50 + x^46 + x^43 + x^42 + x^40 + x^38 + x^37 + x^35 + x^34 + x^33 + x^25 + x^23 + x^22 + x^21 + x^18 + x^16 + x^14 + x^13 + x^12 + x^11 + x^10 + x^8 + x^3 + x^2 + x

key = sum(k*x^i for i,k in enumerate(Kr.gens()))
kvars = Kr.gens()
for _ in range(768):
    key = key*a
    value = key + b
    xi = sum(value[i] for i in range(0, 10, 2))
    g = [kvars.index(k) for k in xi.variables()]
    print(g)
```

Once we have these expressions, we have enough information to solve the system of linear equations to recover the key. But not all of the equations we found will be true as we assumed the `ybit` will always be zero, when in fact it will only be zero most of the time. Luckily, we have 768 equations and we only need 256, so we can continually randomly pick 256 equations and see if we get a solution with those. When we choose 256 equations that all hold true, we should be able to solve the system and decrypt the flag.

To solve the system of equations, we write each expression as rows of a $256 \times 256$ matrix $A$ and compute $A^{-1} \mathbf{v}$, where $\mathbf{v}$ is the corresponding `xbit`s vector.

```py
from random import sample
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes

P.<x> = PolynomialRing(GF(2))
q = P.irreducible_element(256, 'minimal_weight')
R.<x> = P.quo(q)

class Cipher:
    def __init__(self, size, params):
        self.size = size
        self.params = params

    def sequence(self, key):
        while True:
            key = key * self.params[0]
            yield key + self.params[1]

    def encrypt(self, key, data, strength):
        for value, pbit in zip(self.sequence(key), data):
            xbit = sum(value[i] for i in range(0, strength, 2))
            ybit = mul(value[i] for i in range(1, strength, 2))
            
            yield int(pbit) ^^ int(xbit) ^^ int(ybit)

a = x^255 + x^252 + x^246 + x^245 + x^240 + x^239 + x^236 + x^234 + x^233 + x^232 + x^231 + x^229 + x^228 + x^227 + x^224 + x^223 + x^218 + x^217 + x^216 + x^215 + x^210 + x^209 + x^204 + x^202 + x^200 + x^198 + x^197 + x^196 + x^192 + x^188 + x^187 + x^182 + x^181 + x^180 + x^178 + x^177 + x^176 + x^174 + x^173 + x^172 + x^167 + x^166 + x^161 + x^160 + x^157 + x^155 + x^154 + x^151 + x^150 + x^149 + x^148 + x^147 + x^146 + x^144 + x^140 + x^137 + x^135 + x^133 + x^132 + x^130 + x^129 + x^126 + x^122 + x^119 + x^118 + x^115 + x^112 + x^111 + x^109 + x^107 + x^106 + x^105 + x^104 + x^101 + x^100 + x^99 + x^97 + x^96 + x^94 + x^92 + x^87 + x^86 + x^84 + x^83 + x^81 + x^79 + x^75 + x^71 + x^69 + x^68 + x^67 + x^66 + x^65 + x^63 + x^62 + x^61 + x^56 + x^55 + x^53 + x^52 + x^50 + x^46 + x^44 + x^43 + x^41 + x^39 + x^38 + x^37 + x^36 + x^35 + x^34 + x^33 + x^32 + x^30 + x^29 + x^27 + x^24 + x^21 + x^17 + x^16 + x^14 + x^13 + x^12 + x^11 + x^10 + x^9 + x^5 + x^4 + x^3 + x + 1
b = x^255 + x^254 + x^250 + x^247 + x^243 + x^242 + x^241 + x^238 + x^235 + x^232 + x^229 + x^227 + x^222 + x^221 + x^219 + x^218 + x^217 + x^216 + x^215 + x^211 + x^207 + x^206 + x^204 + x^202 + x^201 + x^197 + x^195 + x^193 + x^192 + x^190 + x^189 + x^188 + x^186 + x^184 + x^181 + x^180 + x^179 + x^178 + x^176 + x^173 + x^172 + x^169 + x^167 + x^165 + x^161 + x^160 + x^158 + x^149 + x^147 + x^146 + x^145 + x^140 + x^138 + x^137 + x^134 + x^133 + x^132 + x^130 + x^129 + x^128 + x^126 + x^125 + x^124 + x^121 + x^120 + x^118 + x^117 + x^114 + x^112 + x^111 + x^110 + x^109 + x^108 + x^107 + x^106 + x^105 + x^101 + x^96 + x^95 + x^94 + x^93 + x^92 + x^90 + x^89 + x^88 + x^86 + x^85 + x^84 + x^83 + x^81 + x^80 + x^79 + x^78 + x^77 + x^76 + x^71 + x^70 + x^69 + x^68 + x^67 + x^64 + x^63 + x^59 + x^56 + x^55 + x^53 + x^50 + x^46 + x^43 + x^42 + x^40 + x^38 + x^37 + x^35 + x^34 + x^33 + x^25 + x^23 + x^22 + x^21 + x^18 + x^16 + x^14 + x^13 + x^12 + x^11 + x^10 + x^8 + x^3 + x^2 + x
result = 69824286833704501471834043923417254326103912707315595840737453739249974863266259092449058810542265536810346421685955365128856715192808287450464619418781355923155781710833586631897182535937891456025282049302526058466298304955387306232279075295308862156912873485647349272079984781574084434511227361370780842056
ciphertext = list(map(int, bin(result)[2:]))
knowns = ciphertext[:768]

eqns = [eval(l) for l in open('eqns', 'r').read().splitlines()]

def eqn_to_vec(eq):
    v = [0]*256
    for i in eq:
        v[i] = 1
    return v

def vec_to_poly(v):
    p = 0
    for i,c in enumerate(v):
        p += c*x^i
    return p

Cs = list(zip(map(eqn_to_vec, eqns), knowns))

for _ in tqdm(range(133333337)):
    E = sample(Cs, 256)
    A = Matrix(GF(2), [e[0] for e in E])
    v = vector(GF(2), [e[1] for e in E])
    if A.is_singular():
        continue
    sol =  A^-1 * v
    key = vec_to_poly(sol)
    cipher = Cipher(256, [a, b])
    pt = list(cipher.encrypt(key, ciphertext, 10))
    if 1 not in pt[:768]:
        flag = long_to_bytes(int(''.join(map(str, pt[768:])), 2))
        print(flag.decode())
        exit()
```

Flag: `Aero{n1c3_ISD_4tt4ck_g00d_j0b!!}`
