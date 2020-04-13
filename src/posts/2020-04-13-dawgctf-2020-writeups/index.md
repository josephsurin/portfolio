---
path: /posts/2020-04-13-dawgctf-2020-writeups
title: DawgCTF 2020 Writeups
date: 2020-04-13
tags: ctf,infosec,writeup,crypto
---

Writeups for some DawgCTF 2020 challenges. I participated on team `misc` and we came #2.

- crypto
    - [Criss Cross, Criss Cross](#criss-cross-criss-cross)
    - [Cha Cha Real Smooth](#cha-cha-real-smooth)

---

# Criss Cross, Criss Cross <a name="criss-cross-criss-cross"></a>

## crypto (450pts)

> see:{LET ME IIIIIIIIIIIIIIN!}
>
> `crypto.ctf.umbccd.io 13375`
>
> (no brute force is required for this challenge)
>
> Author: pleoxconfusa

`client.py`:

```python
# -*- coding: utf-8 -*-
"""
Welcome to the CBC-MAC oracle!
Our oracle's function is a CBC message authentication code function!
The oracle is found at umbccd.io:13375, and your methods are:
    tst - returns a 16 byte MAC followed by its message
    vfy - verifies the contents of the message after the : in "vfy:...",
          returning a status message of the result.

@author: pleoxconfusa
"""

import socket

BLOCK_SIZE = 16
pad = lambda s: s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) % BLOCK_SIZE) * b'\0'


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('crypto.ctf.umbccd.io', 13375)
sock.connect(server_address)

#available methods: flg, enc, dec.


msg = 'tst'.encode()
sock.sendall(msg)
tst = sock.recv(1024)
print(tst)#not decoded, because now the oracle sends encrypted bytes.

mac = tst[:BLOCK_SIZE]
txt = tst[BLOCK_SIZE:]

msg = 'vfy:'.encode() + mac + txt #sanity check.
sock.sendall(msg)
res = sock.recv(1024)#receive the encryption as 16 bytes of iv followed by ct.
print(res)

msg = 'vfy:'.encode() + mac + pad(txt) #sanity double check, trying to win by padding.
sock.sendall(msg)
res = sock.recv(1024)#receive the encryption as 16 bytes of iv followed by ct.
print(res)

msg = b'vfy:' + mac + b'The first 16 bytes do not authenticate this message.' #sanity triple check
sock.sendall(msg)
res = sock.recv(1024)
print(res) 
    
sock.close()
```

### Solution

We are given access to a [CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC) oracle. The oracle's functionality is limited to giving us a single plaintext message and its MAC, and verifying any number of messages. The plaintext message and MAC that the oracle gives is the exact same every time. The goal of the challenge is to verify any message other than the one given.

The CBC-MAC of a message $m$ is the last ciphertext block of the encryption of $m$ using an IV of $\textbf{0}$.

<img src="./assets/cbc-mac.svg" style="background: white; padding: 16px"></img>

We can easily create a message different to $m$ whose CBC-MAC is the same as the CBC-MAC for $m$. We do this by appending the XOR between $\text{CBC-MAC}(m)$ and $m_1$ (where $m_1$ is the first plaintext block of $m$), and the remaining plaintext blocks of $m$ to $m$ itself. When the CBC-MAC is calculated for this message, it will be the same as the CBC-MAC for $m$. Visually:

<img src="./assets/cbc-mac-attack.svg" style="background: white; padding: 16px"></img>

Here, we take $m'_1 = m_1 \oplus \text{MAC}$ and $m'_2 = m_2$, $m'_3 = m_3$, and so on. This produces the same MAC as $\text{CBC-MAC}(m)$ because when $m'_1$ is XORed with $\text{MAC}$, the result is $m_1$ and so the remainder of the encryption process is identical to process for computing $\text{CBC-MAC}(m)$.

Implementation:

```python
from pwn import xor, remote
BLOCK_SIZE = 16
pad = lambda s: s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) % BLOCK_SIZE) * b'\0'

conn = remote('crypto.ctf.umbccd.io', 13375)
conn.sendline('tst')
tst = conn.recv()
mac = tst[:16]
msg = pad(b'The first 16 bytes authenticate this message.')
m = mac + msg + xor(mac, msg[:16]) + msg[16:]
conn.send(b'vfy:'+m)
print(conn.recv().decode())
```

Flag: `DawgCTF{Wh@t_@_w3ird_m3$$@ge}`

---

# Cha Cha Real Smooth <a name="cha-cha-real-smooth"></a>

## crypto (500pts)

> Can you crack RSA?
>
> `crypto.ctf.umbccd.io 13374`
>
> (no brute force is required for this challenge)
>
> Author: pleoxconfusa

`client.py`:

```python
# -*- coding: utf-8 -*-
"""
Welcome to the RSA oracle!
Our oracle's function is RSA encryption!
The oracle is found at umbccd.io:13374, and your methods are:
    flg - returns the encrypted flag as bytes
    nnn - returns the N of the rsa function as bytes
    enc - returns the encryption of the message after the : in "enc:..."
          as a bytes representation of an int.
    dec - returns the decryption of the ciphertext int in bytes after the : in "dec:..."
          as a bytes string.
    
@author: pleoxconfusa
"""

import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('crypto.ctf.umbccd.io', 13374)
sock.connect(server_address)

#available methods: flg, enc, dec, nnn.


#public knowledge, may be useful later.
#msg = 'nnn'.encode()
#sock.sendall(msg)
#ct = sock.recv(1024)

msg = 'flg'.encode()
sock.sendall(msg)
ct = sock.recv(1024)
print("flag ct: ",ct) 

#msg = b'dec:' + ct
#sock.sendall(msg)
#print(sock.recv(1024))
    
sock.close()
```

### Solution

The RSA encryption/decryption oracle gives us the flag ciphertext, $c$, and the public modulus, $n$, and allows us to encrypt/decrypt any message (except for the flag ciphertext). The server sends and receives values as bytes. Although we can't ask for the decryption of $c$ directly, the decryption of $c + n$ will give the decryption of $c$ while appearing different to the oracle. This follows from the fact that $n \equiv 0 \pmod n$ and the following properties of modular arithmetic:

$$\begin{aligned} ka &\equiv kb \pmod m \\ a + c &\equiv b + d \pmod m \end{aligned}$$

given $a \equiv b \pmod m$, $c \equiv d \pmod m$ and for all integers $k$.

Note: If we ask for the encryption of `\x01`, we see that the server returns back

```
\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
```

This tells us that the server expects and sends bytes in little endian and up to 128 bytes (RSA modulus is 1024 bits).

Implementation:

```python
from Crypto.Util.number import *
from pwn import remote

conn = remote('crypto.ctf.umbccd.io', 13374)
conn.send('flg')
c = bytes_to_long(conn.recv()[::-1])
conn.send('nnn')
n = bytes_to_long(conn.recv()[::-1])
conn.send(b'dec:'+long_to_bytes(c+n)[::-1])
m1 = conn.recv()
print(m1)
```

Flag: `DawgCTF{Wh0_N3eds_Qu@n7um}`
