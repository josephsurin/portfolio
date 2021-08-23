---
path: /posts/2021-08-10-rarctf-2021-a3s-writeup
title: RaRCTF 2021 - A3S
date: 2021-08-10
tags: ctf,infosec,writeup,crypto
---

This was a nice challenge from an excellent CTF.

# A3S

> I don't like these bits that's why we're using trits!

## Solution

The cipher is almost identical to AES in structure so I won't go over how it works in detail. I highly recommend studying AES (reading Wikipedia and trying to implement it yourself is good). It would have taken me a lot longer to solve the challenge if I didn't already have a general understanding of how AES works.

A3S differs to standard AES in a couple of ways:

- Instead of bits, trits are used; these take on one of three values instead of just two
- Instead of bytes, we have trytes which are three trits
- The block size is 9 trytes
- There are 28 rounds
- The shift rows and mix columns steps are similar (in structure) to AES, but obviously differs to work with trits and trytes
- **The SBOX is an affine transformation**

### General Idea

Given that we only have a very small amount of known plaintext/ciphertext and that there are 28 rounds, my first suspicion was that the SBOX was completely linear/affine. This would mean that we can form a linear system of equations involving plaintext trytes, key trytes and ciphertext trytes which might be able to help us recover the flag. So the idea is simple; get a symbolic representation of the plaintext and key trytes, then run them through the cipher (i.e. encrypt the plaintext with the key) to get the ciphertext in terms of the plaintext and key trytes. Then, we substitute our known plaintext/ciphertext to get a bit of information about the key. Finally, we add our flag ciphertext blocks to the system and try to solve for the unknown plaintext variables. It seems easy enough, but of course, the devil is in the (implementation) details.

### Setting the Stage

In regular AES, bytes are represented as elements of $\mathbb{F}_{2^8} \cong \mathbb{F}_2[x]/(x^8 + x^4 + x^3 + x + 1)$. In A3S we have something similar for trytes; they are represented as elements of $\mathbb{F}_{3^3} \cong \mathbb{F}_3[z]/(z^3 + z^2 + 2)$. For example, the tryte $(1, 0, 2)$ is the element $1 + 2z^2$. It is important that we have this representation as it allows us to write each step of the encryption process in terms of operations on elements in this field.

So the current goal is: represent each step as operations on elements in this finite field so that we can get an algebraic expression for the ciphertext in terms of the plaintext and key. We'll briefly go through the approach for each step.

#### ApplyRoundKey

For a state $M \in M_{3 \times 3}(\mathbb{F}_{3^3})$ (a $3 \times 3$ matrix with entries in the finite field) and key $K \in M_{3 \times 3}(\mathbb{F}_{3^3})$, we apply the key to the plaintext via matrix addition. i.e. the new state after applying the key is $M' = M + K$.

#### ShiftRows

All we need to do for this is rearrange entries of the state matrix $M$. The first row remains unchanged, while the second row is rotated left by one and the third row is rotated left by two:

$$
\begin{aligned}
    M'_{1, 1} &= M_{1, 1} \quad M'_{1, 2} = M_{1, 2} \quad M'_{1, 3} = M_{1, 3} \\
    M'_{2, 1} &= M_{2, 2} \quad M'_{2, 2} = M_{2, 3} \quad M'_{2, 3} = M_{2, 1} \\
    M'_{3, 1} &= M_{3, 3} \quad M'_{3, 2} = M_{3, 1} \quad M'_{3, 3} = M_{3, 2} \\
\end{aligned}
$$

#### MixColumns

In regular AES, the MixColumns step can be represented with matrix multiplication. We'll do the same here. This step _mixes_ the trytes in each column by using them as coefficients of a polynomial in $\mathbb{F}_{3^3}[X]/(f)$ ($f$ is a known polynomial) and multiplying them by some fixed constant polynomial $c(X)$. To determine a matrix representation, we let the column entries be $a_0, a_1, a_2$ and multiply $a_0 + a_1 X + a_2 X^2$ by $c(X)$. We then look at the coefficients of the result:

$$
\begin{aligned}
    (a_0 + a_1 X + a_2 X^2)c(X) &\equiv (a_0 + a_1 X + a_2 X^2) ((1 + 2z) + (2 + z^2)X + (1 + z + z^2)X^2) \pmod{f(X)} \\
                                &\equiv ((1 + 2z) a_0 + (2 + 2z + 2z^2) a_1 + (2 + 2z^2) a_2) + \\
                                &\quad  ((2 + z^2) a_0 + (1 + z^2) a_1 + (1 + z^2) a_2) X \\
                                &\quad  ((1 + z + z^2) a_0 + (1 + z^2) a_1 + (2 + z + z^2) a_2) X^2
\end{aligned}
$$

So the operation of mixing a single column can be represented by left multiplication by the matrix

$$
\begin{bmatrix}
    1 + 2z & 2 + 2z + 2z^2 & 2 + 2z^2 \\
    2 + z^2 & 1 + z^2 & 1 + z^2 \\
    1 + z + z^2 & 1 + z^2 & 2 + z + z^2
\end{bmatrix}
$$

#### SubBytes

Now for the star of the show. First we map integers in $[0, 26]$ to elements of $\mathbb{F}_{3^3}$ using a natural mapping. Once we do that, we see that the first few entries of the SBOX are given by

$$
(2z, 2z^2 + 2z + 1, z^2 + 2z + 2, z^2 + 2, \cdots)
$$

if this is a linear or affine transformation as we suspect, then we must have $0$ mapping to $2z$. If this is the case, then the linear transformation part must by multiplication by $2z^2 + 1$. Indeed, we can go and check for the remaining entries that $\mathrm{SBOX}(x) = (2z^2 + 1)x + 2z$.

### Obtaining a Linear System

Now that we have each step as algebraic operations, we want to obtain expressions for the ciphertext in terms of the plaintext and key. When we substitute our known plaintext/ciphertext, and unknown plaintext, we'll be able to solve this system for the unknown plaintext variables to recover the flag.

To do this in Sage, we can define a polynomial ring over $\mathbb{F}_{3^3}$ in the variables $m_1, m_2, \ldots, m_9, k_1, k_2, \ldots, k_{252}$ for the plaintext trytes and all the round key trytes (we don't care about the key schedule, just let each tryte be it's own variable).

### Solving the Linear System

We solve the linear system for $m_1, \ldots, m_9$ using Gröbner bases. Because of the ordering of the result of the Gröbner basis computation, the "smallest" polynomials come first and to our luck, the first nine are of the form $m_i - c_i$ so we can simply read off the plaintext trytes from these!

```py
from helpers import * # import functions from the handout code

T.<z> = GF(3^3, modulus=x^3 + x^2 + 2)
R.<X> = PolynomialRing(T)
RR.<X> = R.quotient((2 + z^2) + (1 + 2*z)*X + (2*z + z^2)*X^2 + (2 + z^2)*X^3)
CONS = (1 + 2*z) + (2 + z^2)*X + (1 + z + z^2)*X^2

def T_to_tyt(t):
    s = list(map(int, t.polynomial().coefficients(sparse=False)))
    return tuple(s + [0]*(3-len(s)))
def T_to_int(t):
    return tri_to_int(list(map(int, t.polynomial())))
def int_to_T(x):
    return sum([b*z^i for i, b in enumerate(int_to_tri(x))])
def byt_to_T(b):
    return [int_to_T(tri_to_int(x)) for x in int_to_tyt(byt_to_int(b))]

def SBOX(x):
    return (2*z^2 + 1)*x + 2*z

def sub_trytes(M):
    return Matrix([[SBOX(x) for x in r] for r in M])

def mix_columns(M):
    S = Matrix(T, [[2*z + 1, 2*z^2 + 2*z + 2, 2*z^2 + 2],
                   [z^2 + 2, z^2 + 1, z^2 + 1],
                   [z^2 + z + 1, z^2 + 1, 2*z^2 + z + 2]])
    return S*M

def shift_rows(M):
    M = [list(r) for r in M.rows()]
    M[1][0], M[1][1], M[1][2] = M[1][1], M[1][2], M[1][0]
    M[2][0], M[2][1], M[2][2] = M[2][2], M[2][0], M[2][1]
    return Matrix(M)

def apply_key(M, K):
    return M+K

def encrypt(M, K):
    subkeys = [Matrix(P, 3, 3, K[i:i+9]) for i in range(0, len(K), 9)]
    NROUNDS = 28
    M = apply_key(M, subkeys[0])
    for r in range(1, NROUNDS-1):
        M = sub_trytes(M)
        M = shift_rows(M)
        M = mix_columns(M)
        M = apply_key(M, subkeys[r])
    M = sub_trytes(M)
    M = shift_rows(M)
    M = apply_key(M, subkeys[-1])

    return M

P = PolynomialRing(T, [f'm{i}' for i in range(1, 10)] + [f'k{i}' for i in range(1, 9*28+1)])
P.inject_variables()
Mgens = P.gens()[:9]
K = P.gens()[9:]

msg = b'sus.'
m = byt_to_int(msg)
m = up(int_to_tyt(m), W_SIZE ** 2, int_to_tyt(0)[0])[-1]
M = byt_to_T(msg)
M += [0]*(9 - len(M))
M = Matrix([M[i:i+3] for i in range(0, 9, 3)])

kp = encrypt(M, K).list()
sus = bytes.fromhex('060f22028ed1')
kc = byt_to_T(sus)
I = []
for i in range(9):
    I.append(kp[i] - kc[i])

flag_enc = bytes.fromhex('0100c9e96d3d0d077804abd35dd3cd1a8eaa873b3cf15bb8e025ecdb2a44eb1009a0b92e1a7af025dc167a122430178d31')
flag_ct_blocks = [byt_to_T(x) for x in chunk(flag_enc)]
M0 = Matrix(P, 3, 3, Mgens)
my_flag_ct = encrypt(M0, K).list()

Q = PolynomialRing(T, [f'm{i}' for i in range(1, 10)])
FLAG_tyts = []
for flag_ct_block in flag_ct_blocks:
    J = I[::]
    for i in range(9):
        J.append(my_flag_ct[i] - flag_ct_block[i])
    G = Ideal(J).groebner_basis()
    V = Ideal([Q(p) for p in G[:9]]).variety()
    FLAG_tyts.append([V[0][m] for m in Mgens])
chunks = []
for F in FLAG_tyts:
    c = [T_to_tyt(x) for x in F]
    chunks.append(int_to_byt(int(tyt_to_int(c))))

print(unchunk(chunks).decode())
```

Flag: `rarctf{wh3n_sb0x_1s_4_5u55y_baka_02bdeff124}`
