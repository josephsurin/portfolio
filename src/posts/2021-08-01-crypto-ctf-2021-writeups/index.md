---
path: /posts/2021-08-01-crypto-ctf-2021-writeups
title: Crypto CTF 2021 Writeups
date: 2021-08-01
tags: ctf,infosec,writeup,crypto
---

There were many nice challenges in this year's Crypto CTF. Here are writeups for just a few. Thanks to the organisers for the fun CTF.

It was nice to watch the scoreboard. The performance of some of the solo players was really impressive and of course, it was unsurprising that Super Guesser and CryptoHackers did so well. I played with 🛹🐻 and we finished in 9th.

---

|Challenge|Tags|Points|Solves|
|---|---|---|---|
|[Triplet](#triplet)|`RSA` `primes`|91|50|
|[Ferman](#ferman)|`diophantine equations`|134|31|
|[RSAphantine](#rsaphantine)|`RSA` `diophantine equations`|142|29|

# Triplet <a name="triplet"></a>

> Fun with RSA, [three times](https://cryp.toc.tf/tasks/Triplet_b00247f67afefeb5b305957e5605dd70a3b8f5ca.txz)!
> 
> `nc 07.cr.yp.toc.tf 18010`

To get the flag, we need to send the server 3 pairs of primes $(p_1, q_1), (p_2, q_2), (p_3, q_3)$ for 3 RSA moduli $N_1 = p_1 q_1, N_2 = p_2 q_2, N_3 = p_3 q_3$ and an exponent pair $(e, d)$ such that $ed \equiv 1 \pmod{\varphi(N_i)}$ for $i = 1, 2, 3$.

Our primes and exponent pair must satisfy the following:

- $p_i$ and $q_i$ are at least 160 bits
- $N_i \neq N_j$ for $i \neq j$ (the three moduli must be unique)
- $1 < e, d < \varphi(N_i)$ (the exponent pair must be smaller than the smallest value of $\varphi(N_i)$)

## Solution

We first note that if we choose the RSA moduli $N_i$ such that all have the same phi value, then the task of finding the exponent pair is equivalent to finding an exponent pair for just one of the moduli; in this case, we can just take `e = 0x10001` and compute the inverse modulo $\varphi(N_i)$ as usual.

The idea will be to choose an initial pair of primes $(p_1, q_1)$ such that they are both quite a bit larger than 160 bits, and that $p_1 - 1$ and $q_1 - 1$ are very smooth. Then, we consider the prime factorisation of $\varphi(N_1)$:

$$
\varphi(N_1) = \varphi(p_1 q_1) = (p_1 - 1)(q_1 - 1) = r_1^{e_1} \cdots r_k^{e_k}
$$

To find primes different to $p_1$ and $q_1$, but still satisfy the desired property of having the same phi value, we split the prime factors of $\varphi(N_1)$ into two almost equally sized partitions to get $r_{i_1}^{e_{i_1}} \cdots r_{i_m}^{e_{i_m}}$ and $r_{j_1}^{e_{j_1}} \cdots r_{j_{k-m}}^{e_{j_{k-m}}}$. To put it in simpler words, and without the potentially confusing notation, we aim to find two similarly sized divisors $s_1, s_2$ of $\varphi(N_1)$. Then, we simply check if $p_2 = s_1 + 1$ and $q_2 = s_2 + 1$ are prime. If they are, then clearly

$$
\varphi(p_2q_2) = (p_2 - 1)(q_2 - 1) = s_1 s_2 = \varphi(N_1)
$$

We can repeat this (by choosing different divisors $s_1, s_2$) as many times as we need to to get different prime pairs.

Note that we need $s_1$ and $s_2$ to be even to have a chance of $s_1 + 1$ and $s_2 + 1$ being prime, so we make sure to include a factor of $2$ in both of them.

```py
def gen_smooth_prime(nbits):
    while True:
        p = 1
        for q in primes(2^nbits):
            r = randint(1, 2)
            p *= pow(q, r)
            if p.nbits() > nbits:
                break
        if is_prime(p+1):
            return p+1

p1, q1 = gen_smooth_prime(300), gen_smooth_prime(300)
phi1 = (p1 - 1)*(q1 - 1)

facs = list(factor(phi1))
count = 0
print('prime pairs:')
print(f'{p1},{q1}')
while True:
    t1 = sample(facs[1:], len(facs)//2 + randint(-4, 4))
    t2 = set(facs) - set(t1) - {facs[0]}
    p2 = 2*prod(f^e for f,e in t1) + 1
    q2 = 2^(facs[0][1] - 1)*prod(f^e for f,e in t2) + 1
    if p2.is_prime() and q2.is_prime():
        assert phi1 == (p2-1)*(q2-1)
        print(f'{p2},{q2}')
        if count == 1:
            break
        count += 1

e = 0x10001
d = pow(e, -1, phi1)
print()
print('exponent pair:')
print(f'{e},{d}')
```

---

## Ferman <a name="ferman"></a>

> Modern cryptographic algorithms are the theoretical foundations and the core technologies of information security. Should we emphasize more?
>
> `nc 07.cr.yp.toc.tf 22010`

The interactivity with the remote server is not particularly very important, so we grabbed some values and worked offline. Here's what the interaction with the server looks like:

```py
❯ nc 07.cr.yp.toc.tf 22010
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+  hi talented participants, welcome to the FERMAN cryptography task!  +
+  Solve the given equations and decrypt the encrypted flag! Enjoy!    +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

| Parameters generation is a bit time consuming, so please be patient :P
| Options:
|	[P]rint encrypted flag
|	[R]eveal the parameters
|	[Q]uit
r
	e = 65537
	isPrime(p) = True
	isPrime(q) = True
	n = p * q
	(p - 656)**2 + (q - 963)**2 = 3320202784812492330524490070537298583580475358728548450007948498435239404111383935472261393153166267639712257379031535179757548500400989893135081700970178060731084720932889896961295442669803924366240918974546190378390524119382950641285466715346539970610795416980113620249722177226012210564608518035226805407159423864613167407510858568222756127114517158647307638966636861101918323443741159674068413027798613063956533716357312649744435105541692341025142443453616433300402390327321129
	m = bytes_to_long(flag)
	c = pow(m, e, n)
| Options:
|	[P]rint encrypted flag
|	[R]eveal the parameters
|	[Q]uit
p
| encrypt(flag) = 1104552869259054521320459367215205626307072267713253798487395615599865150615771104210691655958867232905435965207275223405884336508705421612571892516997702690774343722384031828549716175794614885021763173120483549596738691533657148009164935996329052504823588221426893090823846947987588608932372042376308326711740581622433481157049398998776013192643927768389651965126117335138857001495164685386619396295392630764239886619115390547376034863534317835500091461280756813701014618629853884
| Options:
|	[P]rint encrypted flag
|	[R]eveal the parameters
|	[Q]uit
```

We have the ciphertext for the flag encrypted with RSA, and a hint about the RSA primes. The hint $s$ is of the form

$$
s = (p - \alpha)^2 + (q - \beta)^2
$$

So the task is essentially to solve this diophantine equation.

## Solution

Let $x = p - \alpha$ and $y = q - \beta$. Then we can write the hint as $s = x^2 + y^2$.

Let's shift gears a bit and think about [Gaussian integers](https://en.wikipedia.org/wiki/Gaussian_integer). We know that $\mathbb{Z}[i]$ is a unique factorisation domain, and that

$$
(x + iy)(x - iy) = (y + ix)(y - ix) = x^2 + y^2
$$

So, we consider the factorisation of the hint $s$ over the Gaussian integers. In our testing with challenge numbers, we get factorisations with not too many different prime factors. The powers of the primes are also $7$, because the challenge is actually to solve $x^2 + y^2 = z^7$. Anyway, once we have the factorisation:

$$
s = (a_1 + ib_1)^7 (a_1 - ib_1)^7 \cdots (a_k + ib_k)^7 (a_k - ib_k)^7
$$

we simply need to choose the $(a_j \pm ib_j)^7$ terms appropriately and take their product to get one of $(x + iy), (x - iy), (y + ix), (y - ix)$. There aren't too many ways to do this, so we just did it manually. Once we have the correct values, we simply take the real and imaginary parts to recover $x$ and $y$. Recovering the primes and thus the flag from this is easy.

```py
from Crypto.Util.number import long_to_bytes

e = 0x10001
c = 2254884511760692550543677177759701327385916425638857251126801005946302220594969474007235171826406865116904613234708577176193957169044090181008427239149308498911578576404808085754865583458844853911431912414771393171813616723744945862448127037501972593643480664587668139499559072554986557545670814778161056994439017826806214489778370715050732844914879377800709399264478886080667231426416093924167450380285443383329398751446093707481626190287153066067239104010982192806032469953797692
alpha, beta = 376, 285
hint = 8932410804466210082068798293693440485791235351577787607682543627874077237652613687000149969398153796005182002677981273951231025004556834240441605542480699383049424620513640705965605366578690748579581927148477562534345010789773556995222478556690487069685566513042054146660803746131657685907282750658593623768822022360014471309514302308794051826808802146162347635902079732296897262491333163698159687407311734313946638466275288441219473689779526045432152213384544079326883483000826693

# GI = GaussianIntegers()
# print(GI(hint).factor())

f1 = (-101487776001296269045575*I + 3449364511579014288098614)^7
f2 = (-382409921*I - 947430964)^7
f3 = (-5*I + 4)^7
x_iy = f1*f2*f3
y = abs(x_iy.real())
x = abs(x_iy.imag())
p, q = x + alpha, y + beta
assert (p - alpha)^2 + (q - beta)^2 == hint
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, int(d), p*q)
print(long_to_bytes(m).decode())
```

---

## RSAphantine <a name="rsaphantine"></a>

> [RSA](https://cryp.toc.tf/tasks/RSAphantine_b1f2e30c7e90cfacb9ef4d0b5ce80abe33d1eb08.txz) and solving equations, but should be a real mathematician to solve it with a diophantine equation?

```
2*z**5 - x**3 + y*z = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613520747411963822349374260144229698759495359592287331083229572369186844312169397998958687629858407857496154424105344376591742814310010312178029414792153520127354594349356721
x**4 + y**5 + x*y*z = 89701863794494741579279495149280970802005356650985500935516314994149482802770873012891936617235883383779949043375656934782512958529863426837860653654512392603575042842591799236152988759047643602681210429449595866940656449163014827637584123867198437888098961323599436457342203222948370386342070941174587735051
y**6 + 2*z**5 + z*y = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613609786612391835856376321085593999733543104760294208916442207908167085574197779179315081994735796390000652436258333943257231020011932605906567086908226693333446521506911058
p = nextPrime(x**2 + z**2 + y**2 << 76)
q = nextPrime(z**2 + y**3 - y*x*z ^ 67)
n, e = p * q, 31337
m = bytes_to_long(FLAG)
c = pow(m, e, n)
c = 486675922771716096231737399040548486325658137529857293201278143425470143429646265649376948017991651364539656238516890519597468182912015548139675971112490154510727743335620826075143903361868438931223801236515950567326769413127995861265368340866053590373839051019268657129382281794222269715218496547178894867320406378387056032984394810093686367691759705672
```

We are given the flag encrypted with RSA, and some hints about the prime generation. The task is essentially to recover $x, y$ and $z$ given the values $c_1, c_2, c_3$ satisfying:

$$
\begin{aligned}
    2z^5 - x^3 + yz &= c_1 \\
    x^4 + y^5 + xyz &= c_2 \\
    y^6 + 2z^5 + zy &= c_3
\end{aligned}
$$

## Solution

The first thing we noticed was that $c_1$ and $c_3$ are _close_. The terms $2z^5$ and $zy$ appear in both, so subtracting them seems like a good idea. We get

$$
\begin{aligned}
    (y^6 + 2z^5 + zy) - (2z^5 - x^3 + yz) &= c_3 - c_1 \\
    \implies y^6 + x^3 &= c_3 - c_1  \\
    \implies (y^2)^3 + x^3 &= c_3 - c_1 \\
    \implies (y^2 + x)(x^2 - xy^2 + y^4) &= c_3 - c_1 \qquad \text{sum of cubes}
\end{aligned}
$$

We can then factor $c_3 - c_1$ and notice that it has a suspicious and small factor $\delta$: `3133713317731333`. Therefore, we suppose $y^2 + x = \delta$. Write $x = \delta - y^2$ and substitute this into $y^6 + x^3 = c_3 - c_1$ to get:

$$
y^6 + (\delta - y^2)^3 = c_3 - c_1
$$

We do not need to bother doing any more work; this is a univariate polynomial in $y$ and we can easily solve for its roots! This allows us to recover $y$. Once we have $y$, we get $x$ for free since $x = \delta - y^2$. Finally, we recover $z$ by plugging in our values for $x$ and $y$ into the second equation $x^4 + y^5 + xyz = c_2$.

```py
from Crypto.Util.number import long_to_bytes

c1 = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613520747411963822349374260144229698759495359592287331083229572369186844312169397998958687629858407857496154424105344376591742814310010312178029414792153520127354594349356721
c2 = 89701863794494741579279495149280970802005356650985500935516314994149482802770873012891936617235883383779949043375656934782512958529863426837860653654512392603575042842591799236152988759047643602681210429449595866940656449163014827637584123867198437888098961323599436457342203222948370386342070941174587735051
c3 = 47769864706750161581152919266942014884728504309791272300873440765010405681123224050402253883248571746202060439521835359010439155922618613609786612391835856376321085593999733543104760294208916442207908167085574197779179315081994735796390000652436258333943257231020011932605906567086908226693333446521506911058

R.<x,y,z> = PolynomialRing(QQ)
delta = 3133713317731333
f1 = y^6 + (delta - y^2)^3 - (c3 - c1)
y = f1.univariate_polynomial().roots()[0][0]
x = delta - y^2
f2 = x^4 + y^5 + x*y*z - c2
z = f2.univariate_polynomial().roots()[0][0]

x = int(x)
y = int(y)
z = int(z)

p = Integer(x**2 + z**2 + y**2 << 76).next_prime()
q = Integer(z**2 + y**3 - y*x*z ^^ 67).next_prime()
n, e = p * q, 31337
c = 486675922771716096231737399040548486325658137529857293201278143425470143429646265649376948017991651364539656238516890519597468182912015548139675971112490154510727743335620826075143903361868438931223801236515950567326769413127995861265368340866053590373839051019268657129382281794222269715218496547178894867320406378387056032984394810093686367691759705672
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, int(d), n)
print(long_to_bytes(m).decode())
```
