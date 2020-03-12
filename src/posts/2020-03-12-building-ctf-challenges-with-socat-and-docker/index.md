---
path: /post/2020-03-12-building-ctf-challenges-with-socat-and-docker
title: Building CTF Challenges with socat and Docker
date: 2020-03-12
tags: ctf,infosec,development
---

A lot of CTFs have challenges which requires the player to connect to some remote TCP service. [Docker](https://www.docker.com/) and [socat](https://linux.die.net/man/1/socat) are two tools that are very helpful when writing these sorts of CTF challenges.

### Overview

We'll use `socat` to execute our program and send user input to its stdin and have its stdout send to the user. This way we can avoid having to deal with sockets in our challenge and can use basic stdin/stdout operations that we should be fairly familiar with. Then we'll use Docker to containerize our challenge for easy deployment.

### The Challenge

We'll use this simple multiplication challenge which asks the user to solve 500 random multiplications to get the flag:

```python
# chall.py
#!/usr/bin/env python

from random import randint

for _ in range(500):
    a, b = randint(2, 1000000000), randint(2, 100000000)
    print(f'What is {a} * {b}?: ')
    try:
        attempt = int(input())
    except:
        print('bad!')
        exit(1)
    if attempt != a*b:
        print('wrong!')
        exit(0)

print('flag{you_can_do_multiplication!}')
```

### Creating the TCP Listener

Next, we'll write a small wrapper using `socat` which will set up the TCP listener for us:

```bash
# wrapper.sh
#!/bin/sh

socat -dd TCP4-LISTEN:"$2",fork,reuseaddr EXEC:"$1",pty,echo=0,raw
```

We give `socat` two address specifications: `TCP4-LISTEN` and `EXEC`.

The `TCP4-LISTEN` keyword instructs `socat` to listen for TCP connections. We pass the parameters `"$2"` (second command line argument) to specify the port to listen on, `fork` to instruct `socat` to create a child process after establishing a connection to allow for more connections, and `reuseaddr` to allow us to restart the service after the master process terminates.

The `EXEC` keyword instructs `socat` to execute a command. We pass the parameters `"$1"` (first command line argument) to specify the command to be run, `pty` to generate a pseudo terminal, `echo=0` to prevent user input from being echoed back to the user and `raw` to disable input/output processing.

If we `chmod +x ./wrapper.sh ./chall.py` and then run `./wrapper.sh ./chall.py 1337` we'll be able to `nc 0.0.0.0 1337` and be prompted with a multiplication question!

If we wanted to have an inactivity timeout (of 30 seconds for example), we could include `-T30` as an option.

### Containerizing with Docker

All we need to do is write a [Dockerfile](https://www.digitalocean.com/community/tutorials/docker-explained-using-dockerfiles-to-automate-building-of-images) and run a few `docker` commands. To keep the image small, we'll use the [python:3.7-alpine](https://hub.docker.com/layers/python/library/python/3.7-alpine/images/sha256-adc6e9c434853cbe206648adc269d9856856a596ada763dc5891ffa4182b4f47?context=explore) image as a base. Then we need to install `socat`, copy the files over, make them executable and then run the wrapper script. Summarised in a Dockerfile, this looks like:

```dockerfile
FROM python:3.7-alpine

RUN apk add --no-cache --update socat

WORKDIR /opt/chall

COPY . .
RUN chmod +x ./chall.py ./wrapper.sh

EXPOSE 1337
CMD [ "./wrapper.sh", "./chall.py", "1337" ]
```

### Building the Image

With our working directory being where the Dockerfile is located, all we need to do to build the image is run:

```
docker build -t ctf-chall .
```

### Running the Container

```
docker run -p 1337:1337 -t ctf-chall
```

There should now be a TCP listener listening on port 1337! You can connect to it with `nc 0.0.0.0 1337` to confirm.

### Testing the Challenge

```python
from pwn import *

conn = remote('0.0.0.0', 1337)

for _ in range(500):
    conn.recvuntil(b'What is ')
    a, b = map(int, conn.recvline().replace(b'?:', b'').split(b' * '))
    print(f'{a}*{b}={a*b}')
    conn.sendline(str(a*b).encode())
print(conn.recvline().decode())
```

Running the solution script should print a 500 multiplication operations, and finally the flag.

### Now What?

Now that we have a containerized challenge, it's easy to deploy this to any server with Docker installed with just a few commands!
