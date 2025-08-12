---
path: /posts/2024-10-03-bsidescbr-2024-ctf-forged-in-fire
title: BSidesCbr 2024 CTF - Forged in Fire
date: 2024-10-03
tags: ctf,writeup,crypto
---

The [cybears](https://twitter.com/cybearsCTF) put on another great CTF at BSides Canberra this year. I played with my team `skateboarding dog` and we ended up placing 1st. This was also the first year we managed to fully clear the crypto category :).

Forged in Fire was a crypto/rev challenge that (surprisingly) ended up with only one solve. The official sources and solutions for all challenges can be found [here](https://gitlab.com/cybears/chals-2024/).

# Forged In Fire

> You enter the blacksmiths forge. He looks up from his anvil and asks "How can I help you today traveller?"
>
> `nc forge.chal.cybears.io 2323`

We are also given the binary that runs on the server.

## Reversing

Since this is a crypto/rev challenge, the first step is to start reversing the binary to understand what it's doing. It's quite small and not stripped, so any decompilation output is fairly readable. The following snippet is the output of IDA, slightly cleaned up:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  cipher_out[17] = __readfsqword(0x28u);
  v21 = 0;
  Prime = 0;
  v20 = 0;
  v22 = 64;
  memset(rsa_p_exported, 0, sizeof(rsa_p_exported));
  memset(cipher_out, 0, 128);
  tag_out[0] = 0LL;
  tag_out[1] = 0LL;
  __gmpz_init(rsa_p, argv, envp);
  __gmpz_init(d_mod_pm1, argv, v3);
  __gmpz_init(rsa_q, argv, v4);
  __gmpz_init(d_mod_qm1, argv, v5);
  __gmpz_init(rsa_d, argv, v6);
  __gmpz_init(qinv_modp, argv, v7);
  __gmpz_init(rsa_n, argv, v8);
  __gmpz_init_set_ui(e_65537, 65537LL);
  __gmpz_init(rsa_pm1, 65537LL, v9);
  __gmpz_init(rsa_qm1, 65537LL, v10);
  __gmpz_init(v33, 65537LL, v11);
  __gmpz_init(sig_out, 65537LL, v12);
  __gmpz_init(hash_to_sign, 65537LL, v13);
  stream = fopen("/home/user/flag.txt", "rb");
  ptr = malloc(0x30uLL);
  if ( !stream )
  {
    puts("Error opening file. Exiting");
    Prime = -1;
    goto LABEL_35;
  }
  v21 = fread(ptr, 1uLL, 0x30uLL, stream);
  if ( v21 == 48 )
  {
    fclose(stream);
    generatePrime((__int64)rsa_p);
    Prime = generatePrime((__int64)rsa_q);
    __gmpz_mul(rsa_n, rsa_p, rsa_q);
    __gmpz_sub_ui(rsa_pm1, rsa_p, 1LL);         // set p-1
    __gmpz_sub_ui(rsa_qm1, rsa_q, 1LL);         // set q-1
    __gmpz_mul(rsa_pm1, rsa_pm1, rsa_qm1);      // compute phi=(p-1)(q-1)
    __gmpz_invert(rsa_d, e_65537, rsa_pm1);     // compute d = e^-1 (mod phi)
    __gmpz_sub_ui(rsa_pm1, rsa_p, 1LL);         // set p-1
    __gmpz_mod(d_mod_pm1, rsa_d, rsa_pm1);      // compute dp = e^-1 (mod p-1)
    __gmpz_mod(d_mod_qm1, rsa_d, rsa_qm1);      // compute dq = e^-1 (mod q-1)
    __gmpz_invert(qinv_modp, rsa_q, rsa_p);     // compute qinv = q^-1 (mod p)
    __gmpz_export(rsa_p_exported, 0LL, 1LL, 1LL, 1LL, 0LL, rsa_p);
    while ( 1 )
    {
      do
      {
        print_menu(is_admin);
        fflush(stdout);
        __isoc99_scanf("%ms", &c);
        s = *(_BYTE *)c;
        if ( s == 113 )
        {
          Prime = 0;
          goto LABEL_35;
        }
      }
      while ( s > 113 );
      if ( s == 51 )
        break;
      if ( s <= 51 )
      {
        switch ( s )
        {
          case '2':
            puts("--== SIGN DATA ==-- ");
            fflush(stdout);
            printf("Enter your message: ");
            fflush(stdout);
            __isoc99_scanf("%ms", &to_sign_str);
            v14 = strlen(to_sign_str);
            if ( (unsigned int)hash((__int64)to_sign_str, v14, (__int64)key) )
            {
              printf("ERROR: Hashing");
              Prime = -6;
              goto LABEL_35;
            }
            free(to_sign_str);
            __gmpz_import(hash_to_sign, v22, 1LL, 1LL, 1LL, 0LL, key);
            sign(
              (__int64)sig_out,
              (__int64)hash_to_sign,
              (__int64)d_mod_pm1,
              (__int64)d_mod_qm1,
              (__int64)qinv_modp,
              (__int64)rsa_p,
              (__int64)rsa_q,
              (__int64)rsa_n,
              &checksum);
            v15 = v20++;
            printf("count = %d ", v15);
            __gmp_printf("sig = 0x%Zx ", sig_out);
            fflush(stdout);
            if ( is_admin == 1 )
            {
              printf("checksum = %d\n", checksum);
              fflush(stdout);
            }
            else
            {
LABEL_32:
              putchar(10);
              fflush(stdout);
            }
            break;
          case '0':
            printf("Enter the password: ");
            fflush(stdout);
            __isoc99_scanf("%ms", &password);
            if ( check_password((const char *)password) )
            {
              puts("Correct password! Welcome admin");
              fflush(stdout);
              is_admin = 1;
            }
            else
            {
              puts("Incorrect password");
              fflush(stdout);
            }
            free(password);
            password = 0LL;
            break;
          case '1':
            puts("--== SIGNING PARAMETERS ==-- ");
            fflush(stdout);
            __gmp_printf("n = 0x%Zx\n", rsa_n);
            fflush(stdout);
            __gmp_printf("e = 0x%Zx\n", e_65537);
            fflush(stdout);
            break;
        }
      }
    }
    puts("--== get encrypted flag ==--");
    fflush(stdout);
    hash((__int64)rsa_p_exported, 0x40u, (__int64)key);
    if ( (unsigned int)encrypt_gcm(ptr, 48LL, key, &iv, cipher_out, tag_out) )
    {
      puts("ERROR: Encrypting flag");
      Prime = -9;
    }
    printf("cipher = ");
    for ( i = 0; i <= 47; ++i )
      printf("%02x", *((unsigned __int8 *)cipher_out + i));
    putchar(10);
    fflush(stdout);
    printf("tag = ");
    for ( i = 0; i <= 15; ++i )
      printf("%02x", *((unsigned __int8 *)tag_out + i));
    goto LABEL_32;
  }
  puts("Error reading file. Exiting");
  Prime = -2;
LABEL_35:
  free(c);
  free(ptr);
  __gmpz_clear(rsa_p);
  __gmpz_clear(d_mod_pm1);
  __gmpz_clear(rsa_q);
  __gmpz_clear(d_mod_qm1);
  __gmpz_clear(rsa_d);
  __gmpz_clear(qinv_modp);
  __gmpz_clear(rsa_n);
  __gmpz_clear(e_65537);
  __gmpz_clear(rsa_pm1);
  __gmpz_clear(rsa_qm1);
  __gmpz_clear(v33);
  __gmpz_clear(sig_out);
  __gmpz_clear(hash_to_sign);
  return Prime;
}
```

The server begins by reading 48 bytes from the `/home/user/flag.txt` file, followed by generating and computing an RSA(-CRT) key pair, and then running a menu loop. After writing the `/home/user/flag.txt` file we can run the program. It presents the following menu:

```
$ ./server
--== Welcome to the Cybears signing service  ==--
What would you like to do today?
1) Print the public parameters
2) Sign some data
3) Get the (encrypted) flag
q) quit
```

Looking at the corresponding switch-case blocks we can see that:

- Option 1 prints the RSA public key `(n, e)`.
- Option 2 reads a string, hashes it, and then calls `sign` on it (with a bunch of RSA-CRT private values as additional arguments). The resulting signature is printed out. Additionally, if `is_admin` is true, a "checksum" value is also printed out.
- Option 3 encrypts the flag using AES GCM, with a hash of the RSA private key prime `p` as the key/iv.

So the goal must be to recover the RSA private key to decrypt the flag.

In option 2, a "checksum" value is printed out if `is_admin` is true. Looking at the binary a bit more, we can notice that there is also a secret option 0 which prompts for a password and sets `is_admin` to true if the password is correct:

```c
          case '0':
            printf("Enter the password: ");
            fflush(stdout);
            __isoc99_scanf("%ms", &password);
            if ( check_password((const char *)password) )
            {
              puts("Correct password! Welcome admin");
              fflush(stdout);
              is_admin = 1;
            }
            else
            {
              puts("Incorrect password");
              fflush(stdout);
            }
            free(password);
            password = 0LL;
            break;
```

The password check is implemented as follows:

```c
_BOOL8 __fastcall check_password(const char *a1)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v7 = __readfsqword(0x28u);
  primes[0] = 2;
  primes[1] = 3;
  primes[2] = 5;
  primes[3] = 7;
  primes[4] = 11;
  primes[5] = 13;
  primes[6] = 17;
  primes[7] = 19;
  primes[8] = 23;
  primes[9] = 29;
  primes[10] = 31;
  primes[11] = 37;
  primes[12] = 41;
  primes[13] = 43;
  primes[14] = 47;
  primes[15] = 53;
  primes[16] = 59;
  primes[17] = 61;
  primes[18] = 67;
  primes[19] = 71;
  primes[20] = 73;
  primes[21] = 79;
  primes[22] = 83;
  primes[23] = 89;
  primes[24] = 97;
  primes[25] = 101;
  primes[26] = 103;
  primes[27] = 107;
  primes[28] = 109;
  primes[29] = 113;
  primes[30] = 127;
  primes[31] = 131;
  primes[32] = 137;
  primes[33] = 139;
  primes[34] = 149;
  primes[35] = 151;
  v5 = strlen(a1);
  v4 = 1;
  for ( i = 0; v5 > i; ++i )
  {
    v2 = toupper(a1[i]);
    if ( ((*__ctype_b_loc())[v2] & 0x400) != 0 )
      v4 *= primes[v2 - 65];
    if ( ((*__ctype_b_loc())[v2] & 0x800) != 0 )
      v4 *= primes[v2 - 22];
  }
  return v4 == -473449774;
}
```

This is essentially taking the password string consisting of characters `[A-Z0-9]`, mapping them to the first 36 primes, taking their product and comparing it against `-473449774` as a 32-bit integer. We'll come back to this later in the crypto section.

Assuming we can pass the password check to set `is_admin` to true, we want to understand what the "checksum" value it gives us is. Looking at the option 2 case:

```c
          case '2':
            puts("--== SIGN DATA ==-- ");
            fflush(stdout);
            printf("Enter your message: ");
            fflush(stdout);
            __isoc99_scanf("%ms", &to_sign_str);
            v14 = strlen(to_sign_str);
            if ( (unsigned int)hash((__int64)to_sign_str, v14, (__int64)key) )
            {
              printf("ERROR: Hashing");
              Prime = -6;
              goto LABEL_35;
            }
            free(to_sign_str);
            __gmpz_import(hash_to_sign, v22, 1LL, 1LL, 1LL, 0LL, key);
            sign(
              (__int64)sig_out,
              (__int64)hash_to_sign,
              (__int64)d_mod_pm1,
              (__int64)d_mod_qm1,
              (__int64)qinv_modp,
              (__int64)rsa_p,
              (__int64)rsa_q,
              (__int64)rsa_n,
              &checksum);
            v15 = v20++;
            printf("count = %d ", v15);
            __gmp_printf("sig = 0x%Zx ", sig_out);
            fflush(stdout);
            if ( is_admin == 1 )
            {
              printf("checksum = %d\n", checksum);
              fflush(stdout);
            }
            else
            {
LABEL_32:
              putchar(10);
              fflush(stdout);
            }
            break;
```

And the implementation of the `sign` function:

```c
__int64 __fastcall sign(
        __int64 sig_out,
        __int64 hash_to_sign,
        __int64 d_mod_pm1,
        __int64 d_mod_qm1,
        __int64 qinv_modp,
        __int64 rsa_p,
        __int64 rsa_q,
        __int64 rsa_n,
        _DWORD *checksum_out)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v18 = __readfsqword(0x28u);
  __gmpz_init(h_pow_dq);
  __gmpz_init(h_pow_dp);
  __gmpz_init(leak);
  __gmpz_powm(h_pow_dq, hash_to_sign, d_mod_qm1, rsa_q);
  __gmpz_powm(h_pow_dp, hash_to_sign, d_mod_pm1, rsa_p);
  __gmpz_tdiv_q_2exp(leak, h_pow_dq, 504LL);
  *checksum_out = __gmpz_get_ui(leak);
  __gmpz_sub(sig_out, h_pow_dp, h_pow_dq);
  __gmpz_mul(sig_out, sig_out, qinv_modp);
  __gmpz_mod(sig_out, sig_out, rsa_p);
  __gmpz_mul(sig_out, sig_out, rsa_q);
  __gmpz_add(sig_out, sig_out, h_pow_dq);
  __gmpz_mod(sig_out, sig_out, rsa_n);
  __gmpz_clear(leak);
  __gmpz_clear(h_pow_dp);
  __gmpz_clear(h_pow_dq);
  return 0LL;
}
```

We see that the "checksum" value is actually the top byte of $h^{d_q} \mod q$. We'll come back to this in the crypto section!

For now, the goal is clear: recover the password and use menu option 0 to set `is_admin` to true. Then somehow use the "checksum" values (which are actually useful leakage of RSA-CRT values) to recover the RSA private key. With the RSA private key primes, we can decrypt the AES GCM encrypted flag.

## Crypto

With the rev part out of the way, we can look to solving the crypto parts of this challenge: recovering a password, and then recovering the RSA private key from the RSA-CRT "checksum" leakage.

### Password Check

The password check works by taking a string of uppercase alphabet and digit characters, mapping each character to one of the first 36 primes, then taking the product of all of those primes, and then comparing (as a 32-bit signed integer) the result against the hardcoded value $-473449774$.

We can write this as

$$
\prod_{i=1}^{36} p_i^{r_i} = -473449774 \pmod{2^{32}}
$$

where $p_i$ is the $i$th prime and $r_i$ represents the number of characters corresponding to that prime that are in the password string (note that order doesn't matter).

The author's approach to solving for a password is to simply bruteforce values that are $-473449774$ plus a multiple of $2^{32}$ and attempt to factor the number, halting if the largest prime factor is less than or equal to $151$ (the 36th prime).

It can also be solved with LLL (overkill) which is what I opted for during the CTF:

```py
load('https://raw.githubusercontent.com/TheBlupper/linineq/main/linineq.py')
from string import ascii_uppercase, digits

def check_pw(pw):
    out = 1
    for c in pw:
        idx = CHARS.index(c)
        out *= PRIMES[idx]
    return out % 2^32

def log_exists(h, g):
    try:
        Z(h).log(g)
    except:
        return False
    return True

PRIMES = Primes()[:36]
CHARS = ascii_uppercase + digits
TARGET = -473449774 % 2^32
TARGET_DIV_2 = TARGET // 2

Z = Zmod(2^32)
g = 5

charset = [c for c in PRIMES if log_exists(c, g)]
n = len(charset)
logs = [Z(c).log(g) for c in charset]

M = Matrix(ZZ, [logs])
log_target = int(Z(TARGET_DIV_2).log(g))
sol = solve_bounded_mod(M, [log_target], [0]*16, [30]*16, 2^30)

pw = ''.join([CHARS[PRIMES.index(charset[i])]*r for i, r in enumerate(sol)]) + 'A'
print('pw:', pw)
print(check_pw(pw) == TARGET % 2^32)
```

The idea is similar to the lattice part of [this](https://jsur.in/posts/2021-09-26-ductf-2021-writeups#yadlp). We choose some base (in this case $g = 5$), then transform the equation to a sum instead of a product by taking logs:

$$
\sum_{i=1}^{36} r_i log_g(p_i) = log_g(-473449774) \pmod{\mathrm{ord}(g)}
$$

Some of the logarithms won't actually exist, but it suffices to only consider the primes for which the logarithm does exist. We use LLL to find small $r_i$ that satisfy this equation and then map those back to the password characters.

This gives us a valid password:

`CCCCCCCCCCCCCCCFFFFFFFFFFFFFGGGGGGGGGGGGGGGJJJJJJJJJJJJJJJLLLLLLLLLLLLLLMMMMMMMMMMMMMMPPPPPPPPPPPPPRRRRRRRRRRRRRRRRUUUUUUUUUUUUUUUUUXXXXXXXXXXXXXXYYYYYYYYYYYYYYYZZZZZZZZZZZZZZZZ2222222222222223333333333333333666666666666666888888888888888A`

### RSA-CRT Leakage

After setting `is_admin` to true, each call to the sign data option gives the top byte of $h^{d_q} \mod q$ in addition to the signature $s$. So that we can play around with ideas easier, it's helpful to reimplement the situation in Python:

```py
from Crypto.Util.number import getPrime, bytes_to_long
from hashlib import sha3_512
import os

p = getPrime(512)
q = getPrime(512)
n = p*q
e = 0x10001
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
dp = d % (p-1)
dq = d % (q-1)
qinv = pow(q, -1, p)

rho = 504
ell = 100
hs = []
sigs = []
leaks = []
for i in range(ell):
    h = bytes_to_long(sha3_512(os.urandom(8)).digest())
    sq = pow(h, dq, q)
    sp = pow(h, dp, p)
    s = sq + q * int(((sp - sq) * qinv % p))
    assert pow(s, e, n) == h
    leak = sq >> rho
    sigs.append(s)
    leaks.append(leak)
```

Here $\ell$ is the number of samples we obtain from the oracle and can be arbitrarily large.

To describe the setting more precisely, each sample is the tuple $(h, s, \hat{s_q})$ where $h$ is the hash of our arbitrarily chosen message, $s$ is the signature value, and $\hat{s_q}$ is the leaked "checksum" value. $\hat{s_q}$ satisfies:

$$
s_q = h^{d_q} = 2^{504} \hat{s_q} + s_q' \pmod q
$$

with $\hat{s_q} < 2^8$ and $s_q' < 2^{504}$.

For some reason, we failed to consider the relation between $\hat{s_q}$ and $s$, until we stumbled across [this paper](https://eprint.iacr.org/2024/1125.pdf) which describes how to recover the RSA private key in this exact scenario.

The idea comes from looking at the equation for $s$:

$$
\begin{aligned}
    s &= s_q + q ((s_p - s_q) q^{-1} \mod p) \\
      &= 2^{504} \hat{s_q} + s_q' + q ((s_p - s_q) q^{-1} \mod p)
\end{aligned}
$$

Then,

$$
s - 2^{504} \hat{s_q} = s_q' + q k
$$

where the left hand side is known, $s_q' < 2^{504}$ and $k$ is some integer.

For the $i$th sample, write the above as:

$$
r_i = s_i - 2^{504} \hat{s_{i,q}} = s_{i,q}' + q k_i
$$

and note that

$$
\begin{aligned}
    r_i - q k_i &= s_{i,q}' \\
    p r_i - pq k_i &= p s_{i, q}' \\
    p r_i - N k_i &= p s_{i,q}'
\end{aligned}
$$

Now, the lattice generated by the rows of

$$
\begin{bmatrix}
    2^{504} & r_1  & r_2 & \cdots & r_{\ell} \\
            & -N                             \\
            &      & -N                      \\
            &      &     & \ddots            \\
            &      &     &        &    -N    \\
\end{bmatrix}
$$

contains the target vector

$$
(2^{504} p, p s_{1,q}, p s_{2,q}, \ldots, p s_{\ell, q})
$$

through the linear combination

$$
(p, k_1, k_2, \ldots, k_{\ell})
$$

Note that each entry in the target vector is of size approximately 1016 bits and so the norm of the target vector is slightly smaller than the norm of other vectors in the reduced basis, for sufficiently large $\ell$. It turns out that $\ell = 350$ is sufficient.

The idea is implemented below (as a continuation of the above script):

```py
from lbc_toolkit import flatter
R = [s - 2^rho * l for s, l in zip(sigs, leaks)]
M = block_matrix(ZZ, [
    [2^rho, Matrix(R)],
    [0,     -n       ]
])
B = flatter(M)
for r in B:
    p_guess = abs(int(r[0])//2^rho)
    if p_guess and n % p_guess == 0:
        print('recovered p:', p_guess, p_guess == p)
```

# Solve Script

`collect.py`

```py
from pwn import *
import json
from tqdm import tqdm

def get_admin():
    conn.sendlineafter(b'quit\n', b'0')
    conn.sendlineafter(b'password: ', b'CCCCCCCCCCCCCCCFFFFFFFFFFFFFGGGGGGGGGGGGGGGJJJJJJJJJJJJJJJLLLLLLLLLLLLLLMMMMMMMMMMMMMMPPPPPPPPPPPPPRRRRRRRRRRRRRRRRUUUUUUUUUUUUUUUUUXXXXXXXXXXXXXXYYYYYYYYYYYYYYYZZZZZZZZZZZZZZZZ2222222222222223333333333333333666666666666666888888888888888A')

def get_public_params():
    conn.sendlineafter(b'quit\n', b'1')
    conn.recvuntil(b'n = ')
    n = int(conn.recvline().decode(), 16)
    conn.recvuntil(b'e = ')
    e = int(conn.recvline().decode(), 16)
    return (n, e)

def sign_data(dat):
    conn.sendlineafter(b'quit\n', b'2')
    conn.sendlineafter(b'message: ', dat)
    conn.recvuntil(b'count = ')
    l = conn.recvline().decode()
    sig = int(l.split('sig = ')[1].split(' ')[0], 16)
    leak = int(l.split('checksum = ')[1])
    return (sig, leak)

def get_enc_flag():
    conn.sendlineafter(b'quit\n', b'3')
    conn.recvuntil(b'cipher = ')
    ct = conn.recvline().decode()
    conn.recvuntil(b'tag = ')
    tag = conn.recvline().decode()
    return (ct, tag)

# context.log_level = 'debug'
# conn = process('./server')
conn = remote('forge.chal.cybears.io', 2323)

get_admin()
n, e = get_public_params()
ct, tag = get_enc_flag()
data_points = []
for i in tqdm(range(360)):
    sig, leak = sign_data(str(i).encode())
    data_points.append((sig, leak))

DATA = {'n': n, 'e': e, 'ct': ct, 'tag': tag, 'data_points': data_points}
open('data-PROD.json', 'w').write(json.dumps(DATA))
```

`finish.sage`

```py
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from lbc_toolkit import flatter
from hashlib import sha3_512
import json

data = json.loads(open('./data-PROD.json', 'r').read())
n = data['n']
e = data['e']
ct = data['ct']
tag = data['tag']
data_points = data['data_points']

rho = 504
ell = len(data_points)
R = [a - 2^rho * b for a,b in data_points]

M = block_matrix(ZZ, [
    [2^rho, Matrix(R)],
    [0,     -n       ]
])

timer = walltime()
print('performing lattice reduction...')
B = flatter(M)
print(f'lattice reduction done... took {walltime(timer):.3f}s')

for r in B:
    p = abs(int(r[0]//2^rho))
    if p and n % p == 0:
        print('ok!', p)
        break

p_bytes = long_to_bytes(p)

limbs = [p_bytes[i:i+8] for i in range(0, len(p_bytes), 8)]

km = sha3_512(b''.join(limbs)).digest()
key = km[:16]
iv = km[16:16+12]
aes = AES.new(key, AES.MODE_GCM, iv)
print(aes.decrypt(bytes.fromhex(ct)).decode())

# cybears{A_sm4ll_l34k_c4n_g0_4_l0ng_w4y_1n_h3r3}
```
