---
path: /posts/2023-03-26-line-ctf-2023-malcheeeeese-writeup
title: LINE CTF 2023 - Malcheeeeese
date: 2023-03-26
tags: ctf,infosec,writeup,crypto
---

I played LINE CTF 2023 with Water Paddler and we got 2nd place. I worked on the crypto challenges and solved Malcheeeeese but failed on Flag Leak Incident 🥲

# Malcheeeeese

> Please break through the authentication and get the flag.
> 
> `nc 34.85.9.81 13000`

`challenge_server.py`:

```py
from server import decrypt, generate_new_auth_token
import socket, signal, json, threading
from socketserver import BaseRequestHandler, TCPServer, ForkingMixIn


address = ('0.0.0.0', 11223)


class ChallengeHandler(BaseRequestHandler):
    def challenge(self, req, verifier, verify_counter):
        authtoken = req.recv(1024).decode().strip()
        ret = decrypt(authtoken, verifier, verify_counter)
        req.sendall(json.dumps(ret).encode('utf-8')+b'\n')

    def handle(self):
        signal.alarm(1500)
        req = self.request
        req.settimeout(60)

        new_auth_token, verifier = generate_new_auth_token()
        req.sendall(b"Leaked Token:"+new_auth_token.hex().encode('utf-8')+b"\n")
        verify_counter = 0
        while True:
            try:
                self.challenge(req, verifier, verify_counter)
            except socket.timeout as e:
                req.sendall(b"Timeout. Bye.\n")
                break
            except socket.error:
                break
            except Exception as e:
                print(e)
                break
            finally:
                if verify_counter < 2:
                    verify_counter+=1

class ChallengeServer(ForkingMixIn, TCPServer):
    request_queue_size = 100

    # For address reassignment on reboot
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)


if __name__ == "__main__":
    TCPServer.allow_reuse_address = True
    server = ChallengeServer(address, ChallengeHandler)
    server.serve_forever()
    
    with server:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.setDaemon(True)
        server_thread.start()
        while True:
            pass
```

`server.py`:

```py
#!/usr/bin/env python3

# crypto + misc challenge

# See generate_new_auth_token() in this file and client.py for details on the authentication token.

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), './secret/'))
from server_secret import FLAG
from common_secret import AES_KEY_HEX, TOKEN_HEX, PASSWORD_HEX

import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

ENCRYPTED_PAYLOAD_SIZE = 136
PREVIOUS_ENCRYPTED_PWD = "72e124ff792af7bc2c077a0260ba3c4a"
AES_IV_HEX = "04ab09f1b64fbf70"
previous_aes_iv = bytes.fromhex(AES_IV_HEX)

# load secrets
aes_key = bytes.fromhex(AES_KEY_HEX)
previous_password = bytes.fromhex(PASSWORD_HEX)

# for authentication
previous_iv_b64 = base64.b64encode(previous_aes_iv)

replay_attack_filter_for_iv = [previous_iv_b64]
replay_attack_filter_for_sig = []
acceptable_token = [] # cf. previous token ( TOKEN_HEX ) was removed
acceptable_password = [b"cheeeeese"] # cf. previous password ( PASSWORD_HEX ) was removed


# Generate new token per request
# Output:
# - new authentication token
# - verifier for EdDSA
def generate_new_auth_token():
    # re-generate token+signature part
    # Generate authentication token ; base64enc( iv for AES ) || AES-256-CTR-Enc( base64enc(password || token || signature), key for AES, iv for AES )
    # Not changed : key for AES, iv for AES, password(PASSWORD_HEX)
    # Change : token, signature

    token = get_random_bytes(15)
    # 1. Generate Signature for token over Ed25519 ( RFC8032 ) 
    sign_key_pair = ECC.generate(curve='Ed25519')
    signer = eddsa.new(key=sign_key_pair, mode='rfc8032')
    signature = signer.sign(token)

    # 2. Encrypt password, token and signature with AES-256-CTR-Enc( base64enc(password || token || signature), key for AES, iv for AES )
    payload =  base64.b64encode(previous_password+token+signature)
    cipher = AES.new(key=aes_key, mode=AES.MODE_CTR, nonce=previous_aes_iv)
    # 3. Generate authentication token ; base64enc( iv for AES) || AES-256-CTR-Enc( base64enc(password || token || signature), key for AES, iv for AES )
    encrypted_payload = base64.b64encode(previous_aes_iv) + cipher.encrypt(payload) 
    
    # add token and signature to filter
    acceptable_token.append(token)
    replay_attack_filter_for_sig.append(base64.b64encode(token+signature)[20:])

    # prepare verifier for EdDSA
    verifier = eddsa.new(key=sign_key_pair.public_key(), mode='rfc8032')

    return encrypted_payload, verifier


# Input : b64password : base64 encoded password
# Output:
# - Is password verification successful? ( True / False )
# - raw passowrd length
# - Error Code ( 0, 1, 2 )
# - Error Message
def verify_password(b64password):
    try:
        password = base64.b64decode(b64password)
    except:
        return False, -1, 1, "Base64 decoding error"

    if password in acceptable_password:
        return True, len(password), 0, "Your password is correct!"
    return False, len(password), 2, "Your password is incorrect."

# Input : b64token_signature : base64 encoded token+signature, verifier, verify_counter
# Output:
# - Is signature verification successful? ( True / False )
# - Error Code ( 0, 1, 2, 3, 4 )
# - Error Message
def verify_signature(b64token_signature, verifier, verify_counter):
    b64token = b64token_signature[:20]
    b64signature = b64token_signature[20:]

    if verify_counter > 1:
        return False, 1, "Err1-Verification limit Error"

    if b64signature in replay_attack_filter_for_sig:
        return False, 2, "Err2-Deactived Token"
    
    try:
        token = base64.b64decode(b64token)
        signature = base64.b64decode(b64signature)
    except:
        return False, 3, "Err3-Base64 decoding error"
    
    try:
        verifier.verify(token, signature)
        if token in acceptable_token:
            return True, 0, "verification is successful"
    except ValueError:
        pass

    return False, 4, "Err4-verification is failed"

def decrypt(hex_ciphertext, verifier, verify_counter):

    flag = ""

    # Length check
    ciphertext = bytes.fromhex(hex_ciphertext)
    if len(ciphertext)!=ENCRYPTED_PAYLOAD_SIZE:
        ret = {
            "is_iv_verified" : False,
            "is_pwd_verified" : False,
            "pwd_len" : -1,
            "pwd_error_number" : -1,
            "pwd_error_reason": "",
            "is_sig_verified" : False,
            "sig_error_number" : -1,
            "sig_verification_reason": "authentication token size MUST be 136 bytes",
            "flag" : ""
        }
        return ret
    
    iv_b64 = ciphertext[:12]
    ciphertext = ciphertext[12:]

    # iv reuse detection
    if iv_b64 in replay_attack_filter_for_iv:
        ret = {
            "is_iv_verified" : False,
            "is_pwd_verified" : False,
            "pwd_len" : -1,
            "pwd_error_number" : -1,
            "pwd_error_reason": "",
            "is_sig_verified" : False,
            "sig_error_number" : -1,
            "sig_verification_reason": "iv reuse detected",
            "flag" : ""
        }
        return ret
    

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=base64.b64decode(iv_b64))
    pt_b64 = cipher.decrypt(ciphertext)

    # password authentication
    is_pwd_verified, pwd_len, pwd_error_number, pwd_error_reason = verify_password(pt_b64[:16])

    # authentication using EdDSA
    is_sig_verified, sig_error_number, sig_error_reason = verify_signature(pt_b64[16:], verifier, verify_counter)

    if True==is_pwd_verified and True==is_sig_verified:
        flag = FLAG
    
    ret = {
        "is_iv_verified" : True,
        "is_pwd_verified" : is_pwd_verified,
        "pwd_len" : pwd_len,
        "pwd_error_number" : pwd_error_number,
        "pwd_error_reason": pwd_error_reason,
        "is_sig_verified" : is_sig_verified,
        "sig_error_number" : sig_error_number,
        "sig_error_reason": sig_error_reason,
        "flag" : flag
    }

    return ret
```

`client.py`:

```py
#!/usr/bin/env python3
# crypto + misc challenge

# How to generate the authentication token
# Given as secret; key for AES, sign_key_pair for EdDSA ( sign_key, verify_key ), token, password
# key for AES, token, password were pre-shared to server.
# 1. Generate Signature for token over Ed25519 ( RFC8032 ) 
# 2. Encrypt password, token and signature with AES-256-CTR-Enc( base64enc(password || token || signature), key for AES, iv for AES )
# 3. Generate authentication token ; base64enc( iv for AES) || AES-256-CTR-Enc( base64enc(password || token || signature), key for AES, iv for AES )
# - password : 12 bytes, random bit-string
# - token : 15 bytes, random bit-string
# - signature : 64 bytes, Ed25519 signature ( RFC8032 )
# - key for AES : 32 bytes, random bit-string
# - iv for AES : 8 bytes, random bit-string
# - payload = base64enc(password || token || signature) : 124 bytes
# - authentication_token ( encrypted_payload ) = base64enc(iv) || AES-256-CTR-Enc ( payload ) : 136 bytes

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), './secret/'))
from client_secret import SIGN_KEY_PAIR_HEX
from common_secret import AES_KEY_HEX, TOKEN_HEX, PASSWORD_HEX

import base64
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Cipher import AES

AES_IV_HEX = "04ab09f1b64fbf70"
aes_iv = bytes.fromhex(AES_IV_HEX)

# load secrets
aes_key = bytes.fromhex(AES_KEY_HEX)
password = bytes.fromhex(PASSWORD_HEX)
token = bytes.fromhex(TOKEN_HEX)
sign_key_pair = ECC.import_key(bytes.fromhex(SIGN_KEY_PAIR_HEX).decode('ascii'))

# 1. Generate Signature for token over Ed25519 ( RFC8032 ) 
signer = eddsa.new(key=sign_key_pair, mode='rfc8032')
signature = signer.sign(token)

# 2. Encrypt password, token and signature with AES-256-CTR-Enc( base64enc(password || token || signature), key for AES, iv for AES )
payload = base64.b64encode(password+token+signature)
cipher = AES.new(key=aes_key, mode=AES.MODE_CTR, nonce=aes_iv)
# 3. Generate authentication token ; base64enc( iv for AES) || AES-256-CTR-Enc( base64enc(password || token || signature), key for AES, iv for AES )
encrypted_pwd_token_sig = cipher.encrypt(payload) 

encrypted_payload = base64.b64encode(aes_iv) + encrypted_pwd_token_sig

# user used PREVIOUS_AUTHN_TOKEN_HEX as authentication token
# print("PREVIOUS_AUTHN_TOKEN_HEX", encrypted_payload.hex())

print("PREVIOUS_ENCRYPTED_PWD_HEX", encrypted_pwd_token_sig[:16].hex())
```

# Solution

The aim of this challenge is to break an authentication protocol based on AES-CTR and Ed25519. To get the flag, we must provide an auth token (i.e. an AES-CTR iv/ciphertext) which decrypts to a controlled password and contains the target token along with a valid signature. Upon connection, the server leaks such a valid auth token (though with a different password), but has some measures in place to prevent simple replay attacks.

Here are some useful facts about the challenge that we can gather from the handout files:

- The AES key and IV used to generate the auth token are fixed (across connections)
- The previous password is also fixed
- The Ed25519 key is regenerated per connection
- The auth token payload size is 136, and is of the form `AES_IV (12) || PW_TOKEN_SIG_B64_ENC (124)`
    - Furthermore, `PW_TOKEN_SIG_B64_ENC` is the AES-CTR ciphertext of the base64 encoding of the password, token, and signature: `PW_B64 (16) || TOKEN_B64 (20) || SIG_B64 (88)`
- We are only able to verify the token twice per connection

In terms of the security measures implemented by the protocol, CTR mode nonce reuse is prevented by ensuring the provided IV is not in the list of used IVs, and signature replay attacks are also prevented in a similar way. The implementation of these are both flawed as they use the base64 encoding of the IV and signature to check for reuse which can be exploited as we'll see soon.

## Recovering the Keystream (Password)

To be able to forge a ciphertext for an arbitrary password, we need to either recover the old password or the keystream for the first 16 bytes more generally. By keystream, we mean the AES-CTR keystream produced by the fixed key and IV pair in the challenge. To be able to hit the verify functions with this IV, we need a way to bypass the IV reuse detection check. The check is performed on the base64 encoding of the IV, which is vulnerable due to [_base64 collisions_](https://stackoverflow.com/questions/53225750/is-it-possible-to-get-collisions-with-base64-encoding-decoding), but we didn't use this for this part of the challenge.

The fixed IV is `BKsJ8bZPv3A=` in base64, and `04ab09f1b64fbf70` in hex. By changing the padding byte to an `A`, we get the base64 string `BKsJ8bZPv3AA` which is `04ab09f1b64fbf7000` in hex (there is a trailing null byte). Using this as the IV will pass the IV reuse detection check, but it will essentially result in the nonce reuse situation, since the [initial counter block is simply set to `nonce || 00..00`](https://github.com/Legrandin/pycryptodome/blob/b3c136287a1a079081d61ff977f791988a805daa/lib/Crypto/Cipher/_mode_ctr.py#L349) anyway.

With the IV being reused, we can start looking towards the `verify_password` function, which provides us with errors depending on the validity of the base64 string that the ciphertext decrypts to. Similarly to padding oracle attacks, an oracle that gives different responses based on the decrypted ciphertext can help a lot in recovering the keystream. In this case, the server will respond with whether or not the decrypted ciphertext is valid base64, and if it is, it will tell us the length of the decoded value.

> Side note on base64 padding: All valid base64 strings must be multiples of 4, and this is achieved through padding with the padding character `=`. A string consisting of `n` base64 characters where `n` is 1 more than a multiple of 4 is not valid (you can't just add three padding characters). This means valid base64 strings will only have either one or two trailing padding characters. However, in Python an arbitrary number of padding characters can be used as long as it is enough.

Since we are reusing the IV, the keystream is the same. So if we simply sent the same ciphertext for the first 16 bytes, the decrypted result should be valid base64 corresponding to the base64 encoding of the old password. For simplicity, let's assume (this also happens to be the case actually) that the previous password's base64 encoding is 16 full bytes of base64 data characters (i.e. it doesn't end in padding). If we modify the last byte, there will be some corresponding change in the decrypted value at the last byte. More specifically, the bytes will satisfy `ct_byte ^ keystream_byte == decrypted_byte`. There are three things that can happen which correspond to different responses from the oracle:

1. `decrypted_byte` is a valid base64 character: In this case, base64 decoding will succeed and result in a password of the same length (12)
2. `decrypted_byte` is not a valid base64 character: In this case, base64 decoding will fail as the padding will be incorrect
3. `decrypted_byte` is the padding character `=`: In this case, base64 decoding will succeed and result in a password of length one less (11)

Clearly, this gives us a direct way of recovering this last keystream byte. We simply try all 256 possible values for `ct_byte` and when the oracle tells us that the length is one less, we know that `ct_byte ^ keystream_byte == ord('=')` and so `keystream_byte = ord('=') ^ ct_byte`.

If we now set the last byte such that the decrypted value will be the padding character `=`, we have the exact same situation when modifying the 15th ciphertext byte. This will lead to recovery of the 15th keystream byte as well.

For the 14th byte, if we set the 15th and 16th bytes such that their decrypted values will be the padding character `=`, something slightly different happens. The number of base64 data characters will be 14 and with two leading padding characters, this is valid base64. However, if we modify the 14th ciphertext byte, there are two things that can happen:

1. `decrypted_byte` is a valid base64 character: In this case, base64 decoding will succeed
2. `decrypted_byte` is not a valid base64 character: In this case, base64 decoding will fail

Gathering these results across the 256 possible values of `ct_byte` is sufficient to uniquely recover `keystream_byte`. Specifically, with these results we know that `(ct_byte ^ keystream_byte) not in { valid_base64_charset }` if the oracle returns an error, and `(ct_byte ^ keystream_byte) in { valid_base64_charset }` if it doesn't. We can build a mapping from length 256 bitstrings to `keystream_byte` values where the bitstring contains a `1` if a `ct_byte` value corresponding to that position results in a valid base64 character, and `0` otherwise:

```py
BITSTRING_MAPPING = {}
for key in range(256):
    v = ''
    for ct in range(256):
        if key^ct in b64_vals:
            v += '1'
        else:
            v += '0'
    assert v not in BITSTRING_MAPPING
    BITSTRING_MAPPING[v] = key
```

Using this, it is possible to recover the rest of the keystream for the first 16 bytes. We can then forge a valid ciphertext for the target password by XORing the keystream with the target password base64 encoded.

## Forging a Signature

Producing a valid ciphertext for the target password is just the first part of the auth token verification. We still need to provide a valid Ed25519 signature for the corresponding random token. If there was no signature replay attack mitigation in place, we could simply send the token/signature part from the leaked auth token. It turns out that it's possible to bypass this mitigation however, so we don't need to break Ed25519 or exploit any malleability issues in Ed25519 itself.

The key to solving this part is [_base64 collisions_](https://stackoverflow.com/questions/53225750/is-it-possible-to-get-collisions-with-base64-encoding-decoding). Essentially, there is an interesting behaviour of base64 decoding which results in two different base64 strings decoding to the same values: 

```py
>>> from base64 import b64decode
>>> b64decode(b'AA==')
b'\x00'
>>> b64decode(b'AB==')
b'\x00'
```

Since the signature replay attack mitigation is implemented via a string comparison on the base64 encodings, we can simply use this behaviour to obtain a "different" signature which will actually be the same signature once decoded.

Note that the signature will always end with two padding characters (because the raw signature is 64 bytes). So without even recovering the keystream for the token and signature, we can simply set the 3rd last byte of the token to a random value and hope that gives us the flag. We just need this to result in the decrypted value at the 3rd last byte to be _slightly_ different to the original value, and in practice this happens without too many attempts.

## Solve Script

```py
from pwn import *
from random import randint
from tqdm import tqdm
from base64 import b64encode, b64decode
import json

from string import ascii_letters, digits
b64a = ascii_letters + digits + '+/'
b64_vals = list(b64a.encode())

BITSTRING_MAPPING = {}
flip = lambda x: x.replace('1','x').replace('0','1').replace('x','0')
for key in range(256):
    v = ''
    for ct in range(256):
        if key^ct in b64_vals:
            v += '1'
        else:
            v += '0'
    assert v not in BITSTRING_MAPPING
    BITSTRING_MAPPING[v] = key
    BITSTRING_MAPPING[flip(v)] = key

PREVIOUS_ENCRYPTED_PWD = bytes.fromhex('72e124ff792af7bc2c077a0260ba3c4a')
DUPED_IV_B64 = bytes.fromhex('424b734a38625a5076334141')

class Oracle:
    def __init__(self):
        self.conn = remote('34.85.9.81', 13000, level='error')

    def retrieve(self):
        token = bytes.fromhex(self.conn.recvline().decode().split(':')[1])
        return token

    def query(self, token):
        self.conn.sendline(token.hex().encode())
        return json.loads(self.conn.recvline().decode())

    def close(self):
        self.conn.close()

first16_keystream = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
curr_enc_pw = PREVIOUS_ENCRYPTED_PWD
for pos in range(1, 17):
    bitmapping = ''
    pos_vals = []
    print('finding val for pos', pos)
    for i in tqdm(range(256)):
        oracle = Oracle()
        token = oracle.retrieve()
        enc_pw = list(curr_enc_pw)
        enc_pw[-pos] = i
        test_token = DUPED_IV_B64 + bytes(enc_pw) + token[12+16:]
        res = oracle.query(test_token)
        oracle.close()
        pos_vals.append(res['pwd_len'])
    B = list(set(pos_vals))
    if len(B) == 3:
        for b in B:
            if pos_vals.count(b) == 1:
                val = pos_vals.index(b) ^ 61
                first16_keystream[-pos] = val
                curr_enc_pw = list(curr_enc_pw)
                curr_enc_pw[-pos] = val ^ 61
                curr_enc_pw = bytes(curr_enc_pw)
                print('good 1', pos, first16_keystream)
                break
    else:
        b0, b1 = B
        for v in pos_vals:
            if v == b0:
                bitmapping += '0'
            elif v == b1:
                bitmapping += '1'
        print(pos, bitmapping)
        if bitmapping in BITSTRING_MAPPING:
            val = BITSTRING_MAPPING[bitmapping]
            first16_keystream[-pos] = val
            curr_enc_pw = list(curr_enc_pw)
            curr_enc_pw[-pos] = val ^ 61
            curr_enc_pw = bytes(curr_enc_pw)
            print('good', pos, first16_keystream)
        else:
            print('bad', pos)

b64_pw = b64encode(b'cheeeeese') + b'===='
enc_pw = xor(first16_keystream, b64_pw)
while True:
    oracle = Oracle()
    token = oracle.retrieve()
    test_token = list(DUPED_IV_B64 + bytes(enc_pw) + token[12+16:])
    test_token[-3] = randint(0, 255)
    res = oracle.query(bytes(test_token))
    print(res)
    if res['flag']:
        print(res['flag'])
        break
    oracle.close()
```

```
$ time python3 solv.py
finding val for pos 1
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 99.85it/s]
good 1 1 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28]
finding val for pos 2
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 99.83it/s]
good 1 2 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 28]
finding val for pos 3
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 99.58it/s]
3 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100100000000000000000000001001111001000000000000000000000010011111111111111111111111111111111111111111111101110110000000011001111
good 3 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194, 83, 28]
finding val for pos 4
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 99.50it/s]
4 1111111100000111111111101111111111111111000001111111111011111111000000000000000000000000000000001111111100000011000000001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
good 4 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 87, 194, 83, 28]
finding val for pos 5
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 98.90it/s]
5 1111111110110000110111111111111111111111101100001101111111111111000000000000000000000000000000001111111100110000000000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
good 5 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82, 87, 194, 83, 28]
finding val for pos 6
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 95.67it/s]
6 0000000000111111111111111101110111111111111111111111111111111111000000000010111101000000000000000000000000101111010000000000000011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
good 6 [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 49, 82, 87, 194, 83, 28]
finding val for pos 7
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 96.09it/s]
7 1111111111000000000000000010001000000000000000000000000000000000111111111101000010111111111111111111111111010000101111111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
good 7 [0, 0, 0, 0, 0, 0, 0, 0, 0, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 8
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 94.04it/s]
8 0010000000000000000000000100111100100000000000000000000001001111111111111111111111111111111111111111111110111011000000001100111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
good 8 [0, 0, 0, 0, 0, 0, 0, 0, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 9
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 93.09it/s]
9 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001000000000000000011111111111111111111111101000010111111111111111111111111010000101111111111
good 9 [0, 0, 0, 0, 0, 0, 0, 142, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 10
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 91.87it/s]
10 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001110111111111111111111110111000011101111111111111111111101110000000000000000000000000000000000001100111111110001000100000000
good 10 [0, 0, 0, 0, 0, 0, 220, 142, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 11
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 88.98it/s]
11 0000000100000000000000001111100000000001000000000000000011111000111111110111011100000000111111001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
good 11 [0, 0, 0, 0, 0, 103, 220, 142, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 12
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 88.90it/s]
12 0000000000000000000000000000000000000000100010001111111100110000111011111111111111111111011100001110111111111111111111110111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
good 12 [0, 0, 0, 0, 3, 103, 220, 142, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 13
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 87.27it/s]
13 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000101111111100001100000000000000000000000000000000001111101111111111111111110000110111111011111111111111111100001101
good 13 [0, 0, 0, 165, 3, 103, 220, 142, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 14
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:02<00:00, 86.22it/s]
14 1111111101111111111000001111111111111111011111111110000011111111000000000000000000000000000000000001000100000000110000001111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
good 14 [0, 0, 72, 165, 3, 103, 220, 142, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 15
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:03<00:00, 83.98it/s]
15 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100000000110011111111111101110111111111111111111111111111111111110000000010001111000100000000000000000000100011110001000000000000
good 15 [0, 179, 72, 165, 3, 103, 220, 142, 66, 49, 49, 82, 87, 194, 83, 28]
finding val for pos 16
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 256/256 [00:03<00:00, 83.31it/s]
16 0000000000000000000000000000000001000100000000000011000011111111111111111101111110110000111111111111111111011111101100001111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
good 16 [10, 179, 72, 165, 3, 103, 220, 142, 66, 49, 49, 82, 87, 194, 83, 28]
{'is_iv_verified': True, 'is_pwd_verified': True, 'pwd_len': 9, 'pwd_error_number': 0, 'pwd_error_reason': 'Your password is correct!', 'is_sig_verified': True, 'sig_error_number': 0, 'sig_error_reason': 'verification is successful', 'flag': 'LINECTF{c576ff588b07a5770a5f7fab5a92a0c2}'}
LINECTF{c576ff588b07a5770a5f7fab5a92a0c2}

real	0m44.819s
user	0m8.517s
sys	0m0.731s
```
