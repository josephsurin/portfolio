---
path: /posts/2020-11-23-dragon-ctf-2020-bit-flip-writeups
title: Dragon CTF 2020 - Bit Flip
date: 2020-11-23
tags: ctf,infosec,writeup,crypto
---

Only managed to solve Bit Flip 1 during the CTF :(. The other challenges were quite interesting.

- [Bit Flip 1](#bit-flip-1)
- [Bit Flip 2](#bit-flip-2)
- [Bit Flip 3](#bit-flip-3)

# Bit Flip 1 <a name="bit-flip-1"></a>

> Flip bits and decrypt communication between Bob and Alice.
>
> nc bitflip1.hackable.software 1337

```python
#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
from gmpy2 import is_prime

FLAG = open("flag", "rb").read()
FLAG += (16 - (len(FLAG) % 16))*b" "


class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256


  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)
    return x & ((1 << num) - 1)


class DiffieHellman:
  def gen_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    while not is_prime(prime):
      iter += 1
      prime = self.rng.getbits(512)
    print("Generated after", iter, "iterations")
    return prime

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    if prime is None:
      prime = self.gen_prime()

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337

  def set_other(self, x):
    self.shared ^= pow(x, self.my_secret, self.prime)

def pad32(x):
  return (b"\x00"*32+x)[-32:]

def xor32(a, b):
  return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x):
  print("bit-flip str:")
  flip_str = base64.b64decode(input().strip())
  return xor32(flip_str, x)


alice_seed = os.urandom(16)

while 1:
  alice = DiffieHellman(bit_flip(alice_seed))
  bob = DiffieHellman(os.urandom(16), alice.prime)

  alice.set_other(bob.my_number)
  print("bob number", bob.my_number)
  bob.set_other(alice.my_number)
  iv = os.urandom(16)
  print(base64.b64encode(iv).decode())
  cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
  enc_flag = cipher.encrypt(FLAG)
  print(base64.b64encode(enc_flag).decode())
```

## Solution

The server is using a custom RNG to generate the prime and private keys for a Diffie Hellman key exchange between Alice and Bob. The seeds used for the RNG are random, except we can slightly control Alice's seed by flipping bits. Notice that if we can determine Alice's seed, we can determine her secret number too and therefore recover the shared secret used as the AES key.

### Recovering Alice's Seed

We are curiously given the number of iterations required by the RNG to generate the prime. We can use this data to mount a timing attack to iteratively recover Alice's seed bit by bit.

First, we inspect how the RNG generates bits. It does so by taking the desired number of bits from the LSB of the `sha256` hash of the seed. If more bits are required, it increments the seed and outputs the desired number of bits from the LSB of the `sha256` hash of that. Since the prime being generated is 512 bits, the call to `self.rng.getbits(512)` will output `sha256(s) + sha256(s+1)`. Effectively, the seed is incremented by 2 for each "iteration" of the prime generation.

Our exploit will start by guessing the LSB of Alice's seed (so it will succeed only 50% of the time, but this is good enough).

For simplicity and ease of working with bit operations, we'll use binary for describing the seed and flip bitstrings.

Now, suppose we don't flip any bits and we see that the number of iterations is `t`. If we flip the second LSB (i.e. using the flip bitstring `10`), then the number of iterations will be either `t-1` or `t+1`. If the second LSB of Alice's seed is a `1`, then flipping that bit will effectively subtract `2` from the seed, so the RNG will require one extra iteration to generate the prime (so we will get `t+1` iterations). On the other hand, if the second LSB of Alice's seed is a `0`, then flipping that bit will effectively add `2` to the seed, so the RNG will require one less iteration to generate the prime (so we will get `t-1` iterations).

Now let `s` be the current known seed of length `l`. Let `f` denote the bit string that you get by flipping each bit in `s` except the last. For example if `s = 1010110`, then `f = 0101000`. Let `num_iters(x)` denote the number of iterations returned by the server when applying a flip bitstring of `x`.

Let

```
A = num_iters(f)
B = num_iters('1'+f)
C = num_iters(s)
D = num_iters('1'+s)
```

Then,

If the `l+1`st LSB of Alice's seed is a `1`, then `B - C == 1`.

If the `l+1`st LSB of Alice's seed is a `0`, then `A - D == 1`.

To see why this holds, suppose for example that the first `l` LSB of Alice's seed is `110010110` and the `l+1`st LSB of the seed is a `1`. Then we have the following:

```
                       <---l--->
    Alice's seed : ...1110010110
[1] flip by '1'+f: ...0111111110
[2] flip by s    : ...1000000000 
```

Notice that the numerical diference between `[2]` and `[1]` will be `2`. Therefore, flipping by `s` will require one extra iteration compared to flipping by `'1'+f`. Hence `B - C == 1`.

Similar reasoning can be applied to show why the other case holds.

We use this to recover each bit in Alice's seed.

### Grabbing The Flag

Now that we have Alice's seed, we can simulate the generation of the prime and her secret number. We use these with Bob's public key to compute the shared key and decrypt the flag.

**Solve script:**

```python
import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwn import remote, process
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import subprocess
import hashlib

class Rng:
    def __init__(self, seed):
        self.seed = seed
        self.generated = b""
        self.num = 0

    def more_bytes(self):
        self.generated += hashlib.sha256(self.seed).digest()
        self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
        self.num += 256


    def getbits(self, num=64):
        while (self.num < num):
            self.more_bytes()
        x = bytes_to_long(self.generated)
        self.num -= num
        self.generated = b""
        if self.num > 0:
            self.generated = long_to_bytes(x >> num, self.num // 8)
        return x & ((1 << num) - 1)

def gen_prime_and_secret(seed):
    rng = Rng(seed)
    prime = rng.getbits(512)
    while not isPrime(prime):
        prime = rng.getbits(512)
    secret = rng.getbits()
    return prime, secret

def connect():
    # return process('./task.py')
    return remote('bitflip1.hackable.software', 1337)

def recv(conn):
    o = conn.recvline().decode().strip()
    print('[<]', o)
    return o

def send(conn, d):
    print('[>]', d)
    conn.sendline(d)

def solve_pow(conn):
    challenge = recv(conn).split(' ')[-1]
    stamp = subprocess.check_output(['hashcash', '-mb28', challenge]).decode().strip()
    send(conn, stamp)

def do_round(conn, x):
    recv(conn)
    x = b64encode(long_to_bytes(int(x, 2)))
    send(conn, x)
    # iters = int(recv(conn).split(' ')[-1])
    iters = int(recv(conn).split('after ')[1].split(' ')[0])
    bob = int(recv(conn).split('number ')[1])
    iv = b64decode(recv(conn))
    ct = b64decode(recv(conn))
    return iters, bob, iv, ct

def num_iters(conn, x):
    return do_round(conn, x)[0]

def flip(x):
    # x is a bit string
    return x.replace('0', 'x').replace('1', '0').replace('x', '1')

conn = connect()
solve_pow(conn)

alice_seed = '0'
t = num_iters(conn, '0')
t2 = num_iters(conn, '10')
if t2 == t - 1:
    alice_seed = '00'
else:
    alice_seed = '10'

for i in range(126):
    f = flip(alice_seed[:-1]) + '0'
    A = num_iters(conn, f)
    B = num_iters(conn, '1'+f)
    C = num_iters(conn, alice_seed)
    D = num_iters(conn, '1'+alice_seed)

    if B - C == 1:
        alice_seed = '1' + alice_seed
    elif A - D == 1:
        alice_seed = '0' + alice_seed
    else:
        print('[!] unexpected branch')
        exit()

    print('[+] alice_seed:', alice_seed)

_, bob, iv, ct = do_round(conn, '0')
prime, secret = gen_prime_and_secret(long_to_bytes(int(alice_seed, 2) + 1))
print('[+] prime:', prime)
print('[+] secret:', secret)
my_number = pow(5, secret, prime)
shared = int(pow(bob, secret, prime)) ^^ 1337
cipher = AES.new(long_to_bytes(shared, 16)[:16], AES.MODE_CBC, IV=iv)
flag = cipher.decrypt(ct)
print('[+] FLAG:', flag)

conn.close()
```

Flag: `DrgnS{T1min9_4ttack_f0r_k3y_generation}`

# Bit Flip 2 <a name="bit-flip-2"></a>

> Flip bits and decrypt communication between Bob and Alice, but this time Bob is not so talkative.
>
> nc bitflip2.hackable.software 1337

```python
#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
from gmpy2 import is_prime

FLAG = open("flag", "rb").read()
FLAG += (16 - (len(FLAG) % 16))*b" "


class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256


  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)
    return x & ((1 << num) - 1)


class DiffieHellman:
  def gen_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    while not is_prime(prime):
      iter += 1
      prime = self.rng.getbits(512)
    print("Generated after", iter, "iterations")
    return prime

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    if prime is None:
      prime = self.gen_prime()

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337

  def set_other(self, x):
    self.shared ^= pow(x, self.my_secret, self.prime)

def pad32(x):
  return (b"\x00"*32+x)[-32:]

def xor32(a, b):
  return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x):
  print("bit-flip str:")
  flip_str = base64.b64decode(input().strip())
  return xor32(flip_str, x)


alice_seed = os.urandom(16)

while 1:
  alice = DiffieHellman(bit_flip(alice_seed))
  bob = DiffieHellman(os.urandom(16), alice.prime)

  alice.set_other(bob.my_number)
  # print("bob number", bob.my_number)
  bob.set_other(alice.my_number)
  iv = os.urandom(16)
  print(base64.b64encode(iv).decode())
  cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
  enc_flag = cipher.encrypt(FLAG)
  print(base64.b64encode(enc_flag).decode())
```

## Solution

The only difference between `Bit Flip 1` and `Bit Flip 2` is that in `Bit Flip 2` we aren't given Bob's public key:

```bash
❯ diff task-1.py task-2.py
79c79
<   print("bob number", bob.my_number)
---
>   # print("bob number", bob.my_number)
```

From `Bit Flip 1`, we know that we are able to control Alice's seed. If we weren't able to do this, the challenge would be impossible, so the task is essentially to find a seed for Alice's RNG that will let us somehow figure out what the shared secret is without needing Bob's public key.

Some initial thoughts I had was to try and bruteforce seeds and look for primes that make the order of the generator (`g = 5`) small. I realised that this approach would not work at all as the order of `g` is rarely small enough since the prime is 512 bits.

I learnt of the intended solution after the CTF. The way to solve the challenge is by forcing Alice's secret to be `0`, so that the shared secret will end up being `1337 ^ 1 = 1336`. This is done by finding a seed such that the `sha256` of the seed after the prime has been generated has at least 8 trailing zeroes. I had no idea about this, but it turns out that hashes for blocks on the Bitcoin blockchain are of this form (the proof-of-work scheme involves finding such strings. read more about it [here](https://en.bitcoin.it/wiki/Proof_of_work) and [here](https://en.bitcoin.it/wiki/Block_hashing_algorithm)). 

The hash of the block is given by `sha256(h)` where `h = sha256(header)` is the `sha256` of the block's header. So to solve the challenge, we search the blockchain for blocks that satisfy `isPrime(sha256(h-2) + sha256(h-1))`. Then, the seed `h-2` will produce a prime, and Alice's secret key will be given by `sha256(h)`, which has 8 trailing zeroes.

To search the blockchain and get the relevant data about each block, we use the [Bitcoin.com Explorer API](https://explorer.api.bitcoin.com/docs/bch/v1/).

**Solve script:**

Finding the block hash:

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
from hashlib import sha256
from tqdm import tqdm
from requests import Session

s  = Session()

def get_blocks_list(block_date=None):
  block_list = []
  d = '' if block_date is None else '?blockDate='+block_date
  block_list = s.get('https://explorer.api.bitcoin.com/bch/v1/blocks'+d).json()
  return [b['hash'] for b in block_list['blocks']], block_list['pagination']['prev']

def get_block_data(block_hash):
  block_data = s.get('https://explorer.api.bitcoin.com/bch/v1/block/'+block_hash).json()
  d = {}
  d['hash'] = block_data['hash']
  d['version'] = block_data['version']
  d['merkleroot'] = block_data['merkleroot']
  d['time'] = block_data['time']
  d['bits'] = block_data['bits']
  d['nonce'] = block_data['nonce']
  d['previousblockhash'] = block_data['previousblockhash']
  return d

def get_block_header(block_data):
  header = int.to_bytes(block_data['version'], 4, 'little')
  header += bytes.fromhex(block_data['previousblockhash'])[::-1]
  header += bytes.fromhex(block_data['merkleroot'])[::-1]
  header += int.to_bytes(block_data['time'], 4, 'little')
  header += bytes.fromhex(block_data['bits'])[::-1]
  header += int.to_bytes(block_data['nonce'], 4, 'little')
  return header

def check_block(header):
  # checks if the block satisfies the condition
  # isPrime(sha256(h-2) + sha256(h-1)) where h
  # is the sha256 hash of the block header
  h = bytes_to_long(sha256(header).digest())
  p = sha256(long_to_bytes(h-2, 32)).digest() + sha256(long_to_bytes(h-1, 32)).digest()
  p = bytes_to_long(p)
  return isPrime(p)

def go(block_date):
  block_list, block_date = get_blocks_list(block_date)
  for block_hash in tqdm(block_list):
    block_data = get_block_data(block_hash)
    header = get_block_header(block_data)
    if check_block(header):
      print('[+] found block:', block_hash)
      print(' |  use seed', long_to_bytes(bytes_to_long(sha256(header).digest()) - 2, 32).hex())
      return True
  return go(block_date)

go(None)
# [+] found block: 000000000000000003cf4d4204d2a2f1fa76e32ae8f4f911c4c630ffd5f50a8f
#  |  use seed 54fb3cbca5ab07e88926a4aa936e7cdff6f3ce64b6645cea511681a661c6240a
```

Grabbing the flag:

```python
from pwn import remote, process
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import subprocess
import hashlib

def connect():
    # return process('./task.py')
    return remote('bitflip2.hackable.software', 1337)

def recv(conn):
    o = conn.recvline().decode().strip()
    print('[<]', o)
    return o

def send(conn, d):
    print('[>]', d)
    conn.sendline(d)

def solve_pow(conn):
    challenge = recv(conn).split(' ')[-1]
    stamp = subprocess.check_output(['hashcash', '-mb28', challenge]).decode().strip()
    send(conn, stamp)

def do_round(conn, x):
    recv(conn)
    x = b64encode(long_to_bytes(int(x, 2)))
    send(conn, x)
    # iters = int(recv(conn).split(' ')[-1])
    iters = int(recv(conn).split('after ')[1].split(' ')[0])
    iv = b64decode(recv(conn))
    ct = b64decode(recv(conn))
    return iters, iv, ct

def num_iters(conn, x):
    return do_round(conn, x)[0]

def flip(x):
    # x is a bit string
    return x.replace('0', 'x').replace('1', '0').replace('x', '1')

conn = connect()
solve_pow(conn)

alice_seed = '0'
t = num_iters(conn, '0')
t2 = num_iters(conn, '10')
if t2 == t - 1:
    alice_seed = '00'
else:
    alice_seed = '10'

for i in range(126):
    f = flip(alice_seed[:-1]) + '0'
    A = num_iters(conn, f)
    B = num_iters(conn, '1'+f)
    C = num_iters(conn, alice_seed)
    D = num_iters(conn, '1'+alice_seed)

    if A - D == -1 or B - C == 1:
        alice_seed = '1' + alice_seed
    elif A - D == 1 or B - C == -1:
        alice_seed = '0' + alice_seed
    else:
        print('[!] unexpected branch')
        exit()

    print('[+] alice_seed:', alice_seed)

target_seed = bytes.fromhex('54fb3cbca5ab07e88926a4aa936e7cdff6f3ce64b6645cea511681a661c6240a')
s = strxor(target_seed, long_to_bytes(int(alice_seed, 2), 32))
_, iv, ct = do_round(conn, bin(bytes_to_long(s))[2:])
shared = 1336
cipher = AES.new(long_to_bytes(shared, 16)[:16], AES.MODE_CBC, IV=iv)
flag = cipher.decrypt(ct)
print('[+] FLAG:', flag)

conn.close()
```

Flag: `DrgnS{B1tc0in_p0w3r_crypt0_brut3}`

# Bit Flip 3 <a name="bit-flip-3"></a>

> Flip bits and decrypt communication between Bob and Alice, but this time Bob is not so talkative and primes are stronger.
>
> nc bitflip3.hackable.software 1337

```python
#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
from gmpy2 import is_prime

FLAG = open("flag", "rb").read()
FLAG += (16 - (len(FLAG) % 16))*b" "


class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256


  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)
    return x & ((1 << num) - 1)


class DiffieHellman:
  def gen_strong_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    strong_prime = 2*prime+1
    while not (prime % 5 == 4) or not is_prime(prime) or not is_prime(strong_prime):
      iter += 1
      prime = self.rng.getbits(512)
      strong_prime = 2*prime+1
    print("Generated after", iter, "iterations")
    return strong_prime

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    if prime is None:
      prime = self.gen_strong_prime()

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337

  def set_other(self, x):
    self.shared ^= pow(x, self.my_secret, self.prime)

def pad32(x):
  return (b"\x00"*32+x)[-32:]

def xor32(a, b):
  return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x):
  print("bit-flip str:")
  flip_str = base64.b64decode(input().strip())
  return xor32(flip_str, x)


alice_seed = os.urandom(16)

while 1:
  alice = DiffieHellman(bit_flip(alice_seed))
  bob = DiffieHellman(os.urandom(16), alice.prime)

  alice.set_other(bob.my_number)
  # print("bob number", long_to_bytes(bob.my_number))
  bob.set_other(alice.my_number)
  iv = os.urandom(16)
  print(base64.b64encode(iv).decode())
  cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
  enc_flag = cipher.encrypt(FLAG)
  print(base64.b64encode(enc_flag).decode())
```

## Solution

I didn't manage to solve this one during the CTF either. It is a deceptively easy challenge though.

This handout code is identical to `Bit Flip 2`, except the primes generated are strong primes:

```bash
❯ diff task-2.py  task-3.py
38c38
<   def gen_prime(self):
---
>   def gen_strong_prime(self):
41c41,42
<     while not is_prime(prime):
---
>     strong_prime = 2*prime+1
>     while not (prime % 5 == 4) or not is_prime(prime) or not is_prime(strong_prime):
43a45
>       strong_prime = 2*prime+1
45c47
<     return prime
---
>     return strong_prime
50c52
<       prime = self.gen_prime()
---
>       prime = self.gen_strong_prime()
```

Taking a look at the prime generation method:

```python
  def gen_strong_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    strong_prime = 2*prime+1
    while not (prime % 5 == 4) or not is_prime(prime) or not is_prime(strong_prime):
      iter += 1
      prime = self.rng.getbits(512)
      strong_prime = 2*prime+1
    print("Generated after", iter, "iterations")
    return strong_prime
```

we see that `prime` is up to 512 bits, so `strong_prime = 2*prime+1` is potentially 513 bits. If we look at the encryption of the flag:

```python
  cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
```

we see that `long_to_bytes` is called with `blocksize=16`.

```
>>> help(long_to_bytes)
Help on function long_to_bytes in module Crypto.Util.number:

long_to_bytes(n, blocksize=0)
    Convert an integer to a byte string.

    In Python 3.2+, use the native method instead::

        >>> n.to_bytes(blocksize, 'big')

    For instance::

        >>> n = 80
        >>> n.to_bytes(2, 'big')
        b'P'

    If the optional :data:`blocksize` is provided and greater than zero,
    the byte string is padded with binary zeros (on the front) so that
    the total length of the output is a multiple of blocksize.

    If :data:`blocksize` is zero or not provided, the byte string will
    be of minimal length.
```

So the call to `long_to_bytes(alice.shared, 16)` (where we assume `alice.shared` is 513 bits since the prime is) will pad the output such that the first 16 bytes at `\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01`.

To get the flag, all we need to do is attempt to decrypt the given ciphertexts with the key `\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01`. After a few attempts, we'll get the flag.

**Solve script:**

```python
from pwn import remote, process
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from base64 import b64encode, b64decode
import subprocess
import hashlib

def connect():
    # return process('./task.py')
    return remote('bitflip3.hackable.software', 1337)

def recv(conn):
    o = conn.recvline().decode().strip()
    print('[<]', o)
    return o

def send(conn, d):
    print('[>]', d)
    conn.sendline(d)

def solve_pow(conn):
    challenge = recv(conn).split(' ')[-1]
    stamp = subprocess.check_output(['hashcash', '-mb28', challenge]).decode().strip()
    send(conn, stamp)

def do_round(conn, x):
    recv(conn)
    x = b64encode(long_to_bytes(int(x, 2)))
    send(conn, x)
    # iters = int(recv(conn).split(' ')[-1])
    iters = int(recv(conn).split('after ')[1].split(' ')[0])
    iv = b64decode(recv(conn))
    ct = b64decode(recv(conn))
    return iters, iv, ct

conn = connect()
solve_pow(conn)

i = 0
while 1:
    _, iv, ct = do_round(conn, '1'*(1+i))
    cipher = AES.new(b'\x00'*15 + b'\x01', AES.MODE_CBC, IV=iv)
    flag = cipher.decrypt(ct)
    if b'Drgn' in flag:
        print('[+] FLAG:', flag)
        break
    i += 1

conn.close()
```

Flag: `DrgnS{C0nst_A3S_K3y_1111111111111!}`
