---
path: /posts/2023-11-12-hkcert-ctf-2023-sign-me-a-flag
title: HKCERT CTF 2023 - Sign me a Flag
date: 2023-11-12
tags: ctf,writeup,crypto
---

# Sign me a Flag (I)

> > 向你揭露 每吋軟弱
> > 數據放著 刪不去我損傷
> >
> > 浮雲藏有天的昏花
> > 我怕我只想還原平凡
> > 銀河藏有星的孤單
> > 如凡人能被愛嗎
>
> No gib flag? No flag!
>
> Note: This is a easier version of the Sign me a Flag (II) challenge, and there is a guide for this challenge [here](https://hackmd.io/@blackb6a/hkcert-ctf-2023-i-en-a58d115f39feab46#%E6%B1%82%E6%97%97%E7%B0%BD%E5%90%8D-I--Sign-me-a-Flag-I-Crypto).
>
> `nc chal.hkcert23.pwnable.hk 28029`

```py
import signal
import os
import hmac
import hashlib
import sys


def tle_handler(*args):
    print('⏰')
    sys.exit(0)

def xor(a, b):
    return bytes(u^v for u, v in zip(a, b))

def sign_message(key_client: bytes, key_server: bytes, message: str) -> bytes:
    key_combined = xor(key_client, key_server)

    signature = hmac.new(key_combined, message.encode(), hashlib.sha256).digest()
    return signature


def main():
    signal.signal(signal.SIGALRM, tle_handler)
    signal.alarm(120)

    flag = os.environ.get('FLAG', 'hkcert23{***REDACTED***}')

    key_server = os.urandom(16)

    for id in range(10):
        action = input('🎬 ').strip()

        if action == 'sign':
            key_client = bytes.fromhex(input('🔑 '))
            message = input('💬 ')
            if 'flag' in message:
                return print('😡')
            signature = sign_message(key_client, key_server, message)
            print(f'📝 {signature.hex()}')
        elif action == 'verify':
            key_client = b'\0'*16 # I get to decide the key :)
            message = input('💬 ')
            signature = bytes.fromhex(input('📝 '))
            if message != 'gib flag pls':
                return print('😡')
            if signature != sign_message(key_client, key_server, message):
                return print('😡')
            print(f'🏁 {flag}')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('😒')
```

## Solution

It is recommended to read the [beginner step-by-step guide](https://hackmd.io/@blackb6a/hkcert-ctf-2023-i-en-a58d115f39feab46#%E6%B1%82%E6%97%97%E7%B0%BD%E5%90%8D-I--Sign-me-a-Flag-I-Crypto) provided by the author (which was made available during the CTF) for a good overview of the challenge and how to approach solving it.

To get the flag from this challenge, we need to forge a MAC for a given target message under the server's secret HMAC key. To help us with this goal, we are provided with a "signing" oracle which lets us generate a MAC for an arbitrary message under a modified key computed by XORing the server's secret key with our provided client key. We can call this signing oracle up to 9 times before we must present a valid MAC for the target message to get the flag.

The issue that we can exploit in this challenge is the way the XOR operation is implemented:

```py
def xor(a, b):
    return bytes(u^v for u, v in zip(a, b))
```

As pointed out in the author's guide, since `zip` is used, if the two byte strings are of different length, the output is the length of the shorter string. This means, if we provide the client key as the single byte `\x00`, the key that gets used to generate the MAC is simply the first byte of the server key. We could then use the given MAC to recover this byte by bruteforcing all 256 possibilities, computing the MAC under that key candidate and then checking if it matches what the server gave us. This could be generalised to the next 15 bytes of the key to recover the full secret key.

However, this would take 16 queries to recover the full key, and we only get 9. The idea is to just bruteforce two bytes at a time which takes a total of 8 queries.

```py
from pwn import *
from tqdm import tqdm
import hmac, hashlib, itertools

def sign_message(key_client, key_server, message):
    key_combined = xor(key_client, key_server)
    signature = hmac.new(key_combined, message.encode(), hashlib.sha256).digest()
    return signature

def sign(key_client, message):
    conn.sendlineafter('🎬 '.encode(), b'sign')
    conn.sendlineafter('🔑 '.encode(), key_client.hex().encode())
    conn.sendlineafter('💬 '.encode(), message.encode())
    conn.recvuntil('📝 '.encode())
    return bytes.fromhex(conn.recvline().decode().strip())

conn = remote('chal.hkcert23.pwnable.hk', 28029)

key_server = b''
for i in range(8):
    s = sign(b'\x00'*2*(i+1), 'asdf')

    for guess in tqdm(range(256*256)):
        cand = key_server + int.to_bytes(guess, 2, 'big')
        if sign_message(b'\x00'*2*(i+1), cand, 'asdf') == s:
            key_server = cand
            print(f'got key:', key_server.hex())
            break

signature = sign_message(b'\0'*16, key_server, 'gib flag pls')
conn.sendlineafter('🎬 '.encode(), b'verify')
conn.sendlineafter('💬 '.encode(), b'gib flag pls')
conn.sendlineafter('📝 '.encode(), signature.hex().encode())
conn.interactive()

# hkcert23{l34k1n9_th3_k3y_b1t_6y_bi7_1s_fun}
```

# Sign me a Flag (II)

> > When I count to three
> > So when I count to three
> >
> > I say one
> > I say two
> > I say three
> > Oh that is you and me
>
> No gib flag? No flag!
>
> Note: This is a harder version of the Sign me a Flag (I) challenge.
>
> `nc chal.hkcert23.pwnable.hk 28009`

```py
import signal
import os
import hmac
import hashlib
from pwn import xor
import sys


def tle_handler(*args):
    print('⏰')
    sys.exit(0)

def sign_message(id: int, key_client: bytes, key_server: bytes, message: str) -> bytes:
    key_combined = xor(key_client, key_server)
    full_message = f'{id}{message}'.encode()

    signature = hmac.new(key_combined, full_message, hashlib.sha256).digest()
    return signature


def main():
    signal.signal(signal.SIGALRM, tle_handler)
    signal.alarm(120)

    flag = os.environ.get('FLAG', 'hkcert23{***REDACTED***}')

    key_server = os.urandom(16)

    for id in range(65536):
        action = input('🎬 ').strip()

        if action == 'sign':
            key_client = bytes.fromhex(input('🔑 '))
            message = input('💬 ')
            if 'flag' in message:
                return print('😡')
            signature = sign_message(id, key_client, key_server, message)
            print(f'📝 {signature.hex()}')
        elif action == 'verify':
            key_client = b'\0'*16 # I get to decide the key :)
            message = input('💬 ')
            signature = bytes.fromhex(input('📝 '))
            if message != 'gib flag pls':
                return print('😡')
            if signature != sign_message(id, key_client, key_server, message):
                return print('😡')
            print(f'🏁 {flag}')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('😒')
```

## Solution

This challenge is almost identical to the first challenge except for three main changes:

1. The `xor` function now uses pwntools `xor`, whose behaviour is the opposite to the `xor` function of the first challenge; the length of the output string is the length of the longest string, and the shorter string is repeated to match the length of the longer one. For example, `xor(b'a', b'bbb') == b'\x03\x03\x03'`.
2. The `sign_message` function now takes an integer `id` parameter and generates a MAC for the string `id||msg` where `id` is represented as a decimal string, `||` denotes string concatenation, and `msg` is the arbitrary string we can provide.
3. We now get `65536` calls to the oracle. In the `i`th call, we can choose to get the MAC of a message where `i` is used for the `id` parameter. We can also choose to get the flag by providing a valid MAC for the message `i||"gib flag pls"` under the server's secret key.

We can no longer use the same technique as in the first challenge because the key used to generate the MAC will always be at least 16 bytes. The new solution idea will depend on the following two observations:

1. In the [definition of HMAC](https://en.wikipedia.org/wiki/HMAC#Definition), the secret key is right padded by null bytes when used internally.
2. As a result of 1., by querying for two MACs (of the same message) where the two client keys are the same except one is one byte longer, we will get two MACs which may be identical depending on a given byte of the server key.

More specifically, suppose we are querying for two MACs. We send the following client keys:

- Query 1 client key: `b'\x00' * 16`
- Query 2 client key: `b'\x00' * 16 + b'x'`

If the first byte of the server's secret key is `b'x'`, then the two resulting MACs will be the same (assuming that the message signed is the same). This is because the `b'x'` will cancel out with the server's key byte at that position, and the resulting internal key will be the same when right padded with null bytes.

The only thing left to put this to use is to be able to generate MACs for the same message. Because the `id` parameter is prepended to the message before being signed, even if we query the oracle with the same message, the actual message that gets signed won't be the same. Fortunately, there is no separator between the `id` and the `msg`, so we can actually get two MACs of the same message when two ids share a prefix. As an example, when we get to `id = 1`, we query with the message `'0'`, then when we get to `id = 10`, we simply query with the empty string as the message. The message that gets signed for both queries will be `'10'`.

In total, we need to check 256 (technically, only 255) candidates per key byte and there are 16 key bytes, so we need to perform a total of 4096 checks. Because we are allowed so many queries, we can do this in a lazy way by using one "pair" of ids to perform one check. As in the example above with `1` and `10`, we use the `id = 1` query to get the baseline result, and then the `id = 10` query to get the result which we check against the baseline to verify if that `(key_idx, key_byte)` guess was correct or not.

Finally, to solve the challenge within the time limits, we might need to batch the queries so that the server processes them all at once without delays due to remote I/O. Since recovery of each key byte is independent of each other, this can be done easily without any issues.

```py
from pwn import *
import hmac, hashlib, itertools

def sign_message(id, key_client, key_server, message):
    key_combined = xor(key_client, key_server)
    message = f'{id}{message}'
    signature = hmac.new(key_combined, message.encode(), hashlib.sha256).digest()
    return signature

def send_batched(ops):
    payload = []
    outs = []
    for op in ops:
        if op == 'nop':
            payload.append(b'nop')
        else:
            payload.append(b'sign')
            payload.append(op[0].hex().encode())
            payload.append(op[1].encode())
            outs.append(op[2])
    conn.sendlineafter('🎬 '.encode(), b'\n'.join(payload))
    out = []
    while True:
        o = conn.clean(1).decode()
        o = [x for x in o.split('\n') if x]
        out += o
        if len(out) - 1 == len(outs):
            break
    sigs = {}
    for i, v in enumerate(out[:-1]):
        sigs[outs[i]] = v.split()[-1]
    conn.unrecv('🎬 '.encode())
    return sigs

numbers = set(range(65536))
useful = {}
j = 0
for i in range(1, 65536):
    i0 = int(str(i) + '0')
    if i in numbers and i0 in numbers:
        numbers.remove(i)
        numbers.remove(i0)
        useful[i] = (j // 256, j % 256)
        j += 1
        if len(useful) == 4096:
            break

conn = remote('chal.hkcert23.pwnable.hk', 28009)

ops = []
for a in tqdm(range(65535)):
    k = int(str(a)[:-1] or '99999999')
    if str(a).endswith('0') and k in useful:
        idx, c = useful[k]
        ops.append((b'\x00' * (16 + idx) + bytes([c]), '', a))
    elif a in useful:
        idx, _ = useful[a]
        ops.append((b'\x00' * (16 + idx), '0', a))
    else:
        ops.append('nop')
all_outs = send_batched(ops)

key_server = bytearray(16)
for a in useful:
    b = int(str(a) + '0')
    idx, c = useful[a]
    if all_outs[a] == all_outs[b]:
        print(f'found! key_server[{idx}] = {c}')
        key_server[idx] = c

print('server key:', key_server)
signature = sign_message(65535, b'\0'*16, key_server, 'gib flag pls')
conn.sendlineafter('🎬 '.encode(), b'verify')
conn.sendlineafter('💬 '.encode(), b'gib flag pls')
conn.sendlineafter('📝 '.encode(), signature.hex().encode())
conn.interactive()

# hkcert23{y0u_h4v3_t0_el1m1n4t3_am6igu17y_7o_m1tig4t3_4mb19ui7y_4t74ck5}
```
