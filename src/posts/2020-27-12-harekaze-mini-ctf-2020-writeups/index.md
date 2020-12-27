---
path: /posts/2020-27-12-harekaze-mini-ctf-2020-writeups
title: Harekaze mini CTF 2020 - Crypto
date: 2020-27-12
tags: ctf,infosec,writeup,crypto
---

Thanks to [@theoremoon](https://twitter.com/theoremoon) for the fun "beginner" challenges.

- [rsa](#rsa)
- [QR](#qr)
- [Curving Torpedo](#curving-torpedo)
- [Wilhelmina says](#wilhelmina-says)

# rsa <a name="rsa"></a>

> Rin Shiretoko: (((All crews of Harekaze were supposed to make key pair, however, I don't have a secret key myself. So let's encrypt this too...)))

```py
from Crypto.Util.number import getStrongPrime, getRandomRange

with open("flag", "rb") as f:
  flag = int.from_bytes(f.read(), "big")

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q
phi = (p-1)*(q-1)
e = 65537
c1 = pow(flag, e, n)
c2 = pow(p + q, e, n)
c3 = pow(p - q, e, n)

print(f"{n=}")
print(f"{e=}")
print(f"{c1=}")
print(f"{c2=}")
print(f"{c3=}")
```

```
n=133957491909745071464818932891535809774039075882486614948793786706389844163167535932401761676665761652470189326864929940531781069869721371517782821535706577114286987515166157005227505921885357696815641758531922874502352782124743577760141307924730988128098174961618373787528649748605481871055458498670887761203
e=65537
c1=35405298533157007859395141814145254094484385088710533905385734792407576252003080929963085838327711405177354982539867453717921912839308282313390558033140654288445877937672625603540090399691469218188262950682485682814224928528948502206046863184746747265896306678488587444125143233443450049838709221084210200357
c2=23394879596667385465597018769822552384439114548016006879565586102300995936951562766011707923675690015217418498865916391314367448706185724546566348496812451258316472754407976794025546555423254676274654957362894171995220230464953432393865332807738040967281350952790472772600745096787761443699676372681208295288
c3=54869102748428770635192859184579301467475982074831093316564134451063250935340131274147041633101346896954483059058671502582914428555153910133076778016989842641074276293354765141522703887273042367333036465503084165682591308676428523152462442280924054400997210800504726635778588407034149919869556306659386868798
```

## Solution

We can factorise $n$ given the hints $c_2 \equiv (p+q)^e \pmod n$ and $c_3 \equiv (p-q)^e \pmod n$. Notice that

$$
\begin{aligned}
    c_2 &\equiv (p+q)^e \pmod n \\
    \implies c_2 &\equiv p^e + q^e \pmod n
\end{aligned}
$$

since the other terms in the expansion of $(p+q)^e$ contain the factor $pq$ which reduces to $0$ modulo $n$. Similarly, we have

$$
c_3 \equiv p^e - q^e \pmod n
$$

Now,

$$
c_2 + c_3 \equiv 2p^e \pmod n
$$

so computing $\gcd(c_2 + c_3, n)$ reveals $p$ and the rest is standard RSA.

```py
from Crypto.Util.number import long_to_bytes

exec(open('./distfiles/output.txt').read())

p = gcd(c2 + c3, n)
q = n//p
phi = (p-1)*(q-1)
flag = pow(c1, inverse_mod(e, phi), n)
print(long_to_bytes(flag).decode())
```

Flag: `HarekazeCTF{RSA_m34n5_Rin_Shiretoko_Ango}`

## QR <a name="qr"></a>

> There are a lot of tasks related to QR code on Japanese CTF. [Citation needed]

```py
import qrcode

with open("flag", "r") as f:
  flag = f.read().strip()

qr = qrcode.QRCode(border=0)
qr.add_data(flag)
qr.make(fit=True)

matrix = qr.get_matrix()
matrix2 = [ [0 for _ in range(len(matrix) - 1) ] for _ in range(len(matrix) - 1)]

for y in range(len(matrix)-1):
  for x in range(len(matrix)-1):
    matrix2[y][x] = (matrix[y][x] + matrix[y+1][x] + matrix[y][x+1] + matrix[y+1][x+1]) % 4

print(matrix2)
```

```
[[3, 2, 2, 2, 2, 3, 2, 1, 1, 1, 2, 2, 1, 1, 2, 3, 3, 3, 3, 2, 1, 1, 2, 3, 2, 2, 3, 2, 2, 2, 2, 3], [2, 1, 2, 2, 1, 2, 2, 0, 1, 2, 2, 3, 3, 1, 0, 2, 0, 0, 3, 2, 2, 1, 1, 3, 2, 2, 2, 1, 2, 2, 1, 2], [2, 2, 0, 0, 2, 2, 2, 1, 2, 3, 3, 3, 3, 2, 2, 2, 2, 3, 3, 2, 2, 2, 3, 0, 2, 2, 2, 2, 0, 0, 2, 2], [2, 2, 0, 0, 2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 3, 1, 1, 3, 3, 3, 2, 2, 0, 0, 2, 2, 2, 2, 0, 0, 2, 2], [2, 1, 2, 2, 1, 2, 2, 2, 0, 0, 2, 2, 3, 3, 2, 1, 2, 3, 3, 3, 2, 1, 2, 3, 2, 2, 2, 1, 2, 2, 1, 2], [3, 2, 2, 2, 2, 3, 2, 2, 3, 3, 2, 2, 3, 3, 2, 2, 2, 2, 3, 3, 2, 1, 1, 2, 2, 2, 3, 2, 2, 2, 2, 3], [2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 1, 1, 1, 2, 3, 3, 3, 2, 2, 3, 3, 3, 3, 2, 1, 2, 2, 2, 2, 2, 2], [1, 0, 0, 1, 1, 1, 2, 3, 2, 1, 1, 1, 1, 1, 2, 2, 3, 3, 2, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 1, 0, 1], [2, 1, 0, 1, 2, 2, 2, 3, 3, 2, 1, 2, 3, 2, 2, 2, 3, 3, 2, 2, 1, 2, 3, 2, 3, 3, 3, 3, 2, 2, 1, 1], [3, 3, 2, 2, 3, 3, 1, 1, 3, 3, 1, 2, 3, 1, 2, 3, 3, 0, 2, 1, 2, 3, 0, 3, 2, 2, 3, 2, 0, 1, 1, 0], [2, 3, 0, 0, 0, 3, 1, 0, 2, 2, 1, 3, 2, 1, 2, 1, 2, 0, 3, 3, 0, 3, 2, 2, 2, 2, 3, 2, 0, 0, 1, 1], [0, 2, 3, 2, 3, 3, 2, 2, 2, 1, 2, 3, 2, 3, 3, 1, 2, 0, 0, 0, 0, 3, 2, 1, 2, 3, 2, 2, 2, 1, 2, 3], [0, 2, 3, 2, 3, 3, 3, 3, 2, 2, 2, 1, 1, 2, 2, 2, 3, 3, 2, 2, 3, 0, 0, 3, 2, 2, 2, 2, 2, 2, 3, 3], [0, 2, 0, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 1, 2, 3, 2, 1, 1, 2, 2, 3, 0, 3, 1, 1, 1, 0, 2, 0, 2], [1, 3, 0, 3, 2, 2, 2, 3, 3, 1, 1, 3, 0, 0, 2, 1, 2, 2, 2, 3, 3, 1, 1, 2, 3, 2, 0, 0, 0, 1, 2, 1], [3, 3, 3, 0, 3, 2, 1, 2, 3, 1, 0, 1, 3, 0, 3, 2, 3, 2, 1, 2, 3, 3, 1, 0, 1, 2, 2, 2, 1, 0, 1, 1], [3, 2, 2, 3, 0, 3, 2, 3, 3, 2, 2, 1, 2, 3, 2, 3, 3, 2, 1, 1, 3, 0, 3, 1, 1, 3, 0, 3, 1, 1, 2, 1], [3, 2, 2, 2, 2, 2, 3, 0, 2, 1, 3, 2, 1, 2, 2, 3, 3, 3, 2, 2, 0, 0, 0, 2, 2, 3, 2, 2, 2, 3, 2, 0], [0, 2, 1, 2, 1, 1, 3, 0, 2, 0, 1, 2, 2, 3, 3, 3, 0, 3, 2, 3, 0, 3, 2, 2, 3, 2, 1, 3, 3, 2, 2, 1], [3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 2, 3, 2, 1, 3, 2, 1, 2, 2, 2, 1, 1, 2, 2, 3, 3, 1, 0, 2, 3], [3, 3, 2, 1, 2, 3, 2, 2, 2, 3, 3, 2, 1, 1, 1, 0, 2, 3, 2, 1, 1, 3, 3, 2, 1, 2, 0, 2, 1, 1, 2, 0], [2, 2, 1, 0, 2, 3, 3, 3, 2, 3, 0, 3, 1, 0, 1, 1, 1, 2, 2, 1, 2, 0, 0, 3, 1, 1, 2, 1, 2, 3, 3, 3], [0, 2, 3, 2, 2, 2, 3, 2, 0, 2, 3, 1, 0, 1, 3, 2, 1, 2, 2, 2, 3, 3, 2, 1, 1, 2, 2, 2, 2, 2, 2, 2], [2, 3, 0, 3, 1, 1, 2, 2, 1, 2, 2, 1, 2, 2, 3, 3, 2, 2, 2, 2, 3, 2, 0, 1, 3, 0, 0, 0, 2, 0, 1, 2], [2, 2, 2, 1, 0, 1, 1, 2, 2, 2, 2, 1, 3, 2, 2, 0, 3, 1, 1, 1, 2, 3, 1, 2, 3, 2, 2, 3, 3, 2, 2, 1], [2, 2, 2, 2, 2, 2, 1, 2, 3, 2, 1, 0, 1, 1, 2, 3, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 2, 3, 2, 1, 0], [3, 2, 2, 2, 2, 3, 2, 1, 2, 1, 0, 0, 1, 2, 3, 3, 2, 2, 1, 2, 3, 1, 1, 3, 2, 1, 1, 2, 2, 0, 0, 0], [2, 1, 2, 2, 1, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 3, 0, 2, 1, 3, 0, 3, 1, 2, 3, 2, 2, 3, 2, 0, 0, 1], [2, 2, 0, 0, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 3, 0, 3, 2, 2, 2, 2, 1, 2, 3, 3, 3, 3, 3, 2, 1, 1], [2, 2, 0, 0, 2, 2, 2, 0, 2, 2, 0, 1, 2, 2, 3, 0, 3, 3, 2, 1, 2, 2, 1, 1, 2, 2, 1, 2, 3, 3, 2, 0], [2, 1, 2, 2, 1, 2, 2, 0, 2, 2, 0, 2, 3, 2, 3, 3, 2, 3, 2, 1, 3, 0, 2, 1, 3, 3, 1, 1, 2, 2, 1, 0], [3, 2, 2, 2, 2, 3, 2, 1, 2, 2, 1, 1, 2, 3, 3, 2, 3, 3, 1, 0, 2, 0, 3, 3, 3, 2, 1, 1, 3, 2, 0, 1]]
```

## Solution

The flag is encoded into an $n \times n$ sized QR code, then an $(n-1) \times (n-1)$ matrix whose entries are computed from the bits in the QR code is outputted. The $(x, y)$ entry in the output matrix is the number of black squares (modulo 4) in the $2 \times 2$ square starting from $(x, y)$ and going to the right and downwards.

This challenge is essentially an exercise with Z3. Just plug in the constraints and wait a couple of seconds. SAT solver go brr...

```py
from z3 import *
from PIL import Image

matrix2 = eval(open('./distfiles/output.txt').read())

m = len(matrix2)
n = m+1
M = [[Int(f'c{y}_{x}') for x in range(n)] for y in range(n)]

s = Solver()
for y in range(n):
    for x in range(n):
        s.add(Or(M[y][x] == 0, M[y][x] == 1))

for y in range(m):
    for x in range(m):
        s.add(matrix2[y][x] == (M[y][x] + M[y+1][x] + M[y][x+1] + M[y+1][x+1]) % 4)

assert s.check()
m = s.model()
matrix = [[m.evaluate(M[y][x]).as_long() for x in range(n)] for y in range(n)]

img = Image.new('1', (n, n))
for y in range(n):
    for x in range(n):
        img.putpixel((x, y), 1-matrix[y][x])
img.save('flag.png')
```

Flag: `HarekazeCTF{d0_y0u_7hink_qr_ch4113ng3_i5_r3411y_in_d3m4nd}`

# Curving Torpedo <a name="curving-torpedo"></a>

> Mei-chan practices to make torpedo curve.

```py
from params import p, a, b

EC = EllipticCurve(GF(p), [a, b])
order = EC.order()

with open("flag", "rb") as f:
    flag = int.from_bytes(f.read().strip(), "big")
    assert flag < order

G = EC.random_point()

print(G.xy())
print((flag * G).xy())

for i in range(10):
    x = randint(2, order-1)
    print((x * G).xy())
```

```
(1799485105087252219265454283737062400478254869531786060964905255776873732974873587858561510957448409807214989270248104936194218445592, 2061198905001105558325440487573584021295005771054973624822380793779541903055566335059411781348312763850159187987731021487610571940526)
(543159670788363927603941544266146844453515277517760742038469631389519681724904864021536007409530673980781011055145299784647639798520, 1216961292218028628033801363201612950727767040922851456847840016802276599210336101920423020479592325107752607334706332445876008060041)
(545578332810450554762303516343401691508406906719179906359050649384587505260314538611776138273685358404772152566371812260724508168342, 1920504318485786606481726849291117355587322097428041045640623057857390773154522782946993215004081737360231314078243743004768677404805)
(1752973115360908830689899614715338516670613977812307928934864267823062728507485234597879416441350102241900619702430322149790627349609, 870493889528921807717329965124340432534153970387097206976791516055900123041327795235604988511219732899740485384643109612464146442496)
(612602904440438305701519488040972464146582273566178673288510900330072464178257382177347057523794789223322766683520940303839351767840, 595403015810179199478107397244304243930739011948870897048037530305945243641652057806535272010280102103141060699414453585316440161738)
(1199560349599067771785997925619390408997952763589684634094871803301276337024298721023272139211730138039734034812517182092007544668938, 3272879655800569085544583874832415842988591211125332151981280885674881917826345688530075039347545196766223940213706370852620309062)
(8386758795265759214271142368146076647804022119450701608723389598988490431997683983805690980018380522345070841944453907527972983668, 1629317954598997602979797377065610518034652480552252834165964817208775353579794711185614887950536382544218676408106163929389758276662)
(895739417417902067817356839568967795280685558861803581806636868772882526489749370428816331096635077838327664288361999844621829536801, 1034720267143182754274786806658891420815108678218600133115169054216757523964490192846236217635979681548504540593861159816681903720438)
(460043918423312763102863533071405210462432146156551086271263854222307194006130501401821329075451725513082829208833828306891667868169, 1078187767437630082390887182316429854228977152276053671625055648005808051048036516585192714646658516588560397309762818351787115203132)
(2256795285447637088196623832148381903043652296199704364155562402254422855690452366220969220102952286578983998424189274382286363912586, 2030620169518621862897862667305100357912087137836402689156005871120126065507848251785303913681353589161987917268982153096465456350078)
(1641529159331113843010100052842807135087957709858687510590522275675602336001461708045409309346611813076745755359838948070509166801426, 2265123379528023116427746276345825318738743739064810954535294824651249903806307656203392409488780206357623814711597594226745994881295)
(1788579668135376412264925309279944766454492644465898695951627356779507463438969113948523351332692852892709787125765271756266723702516, 1488202351075234603790286606003953088089286086650869216087006421631582915937981876735882581614840149798769751841387804007088115208977)
```

## Solution

The first thing we notice is that the parameters of the elliptic curve are unknown. The obvious first step would be to recover these parameters; since this is a "beginner" CTF, we just hope that the curve order turns out to be smooth and we can easily solve the discrete log problem to get the flag.

Recall the Weierstrass equation for elliptic curves:

$$
y^2 \equiv x^3 + ax + b \pmod p
$$

We have more than 10 $(x_i, y_i)$ pairs satisfying this equation at our disposal. Let's see how to recover $a, b$ and $p$ from them.

Let $z_i = (y_{i+1}^2 - x_{i+1}^3) - (y_i^2 - x_i^3)$ and $w_i = x_{i+1} - x_i$. Then,

$$
\begin{aligned}
    z_i &\equiv aw_i \pmod p \\
    \implies z_i &= aw_i + k_ip \qquad k_i \in \mathbb{Z}
\end{aligned}
$$

So if we multiply $z_i$ by $w_{i+1}$ and $z_{i+1}$ by $w_i$, their difference will be a multiple of $p$:

$$
\begin{aligned}
    z_i w_{i+1} &= a w_i w_{i+1} + k_i w_{i+1} p \\
    z_{i+1} w_i &= a w_{i+1} w_i + k_{i+1} w_i p \\
    z_i w_{i+1} - z_{i+1} w_i &= (k_i w_{i+1} - k_{i+1} w_i) p
\end{aligned}
$$

If we do this for a few points, taking their gcd reveals $p$.

Once we have $p$, recovering $a$ and $b$ is easy.

$$
\begin{aligned}
    a &\equiv z_0 w_0^{-1} \pmod p \\
    b & \equiv y_0^2 - x_0^3 - ax_0 \pmod p
\end{aligned}
$$

After reconstructing the curve, we find that the order is smooth! Solving the ECDLP can be done pretty quickly.

```py
from Crypto.Util.number import long_to_bytes

data = open('./distfiles/output.txt').read().splitlines()
G = eval(data[0])
flagG = eval(data[1])
pts = [eval(p) for p in data[2:]]

# recover p
Z = [(pts[i+1][1]^2 - pts[i+1][0]^3) - (pts[i][1]^2 - pts[i][0]^3) for i in range(len(pts)-1)]
W = [pts[i+1][0] - pts[i][0] for i in range(len(pts)-1)]
p = gcd([Z[i]*W[i+1] - Z[i+1]*W[i] for i in range(len(Z)-1)])

# recover a
a = Z[0]*inverse_mod(W[0], p) % p

# recover b
x,y = pts[0]
b = (y^2 - x^3 - a*x) % p

E = EllipticCurve(GF(p), [a, b])
n = E.order() # order is conveniently smooth

flag = discrete_log(E(flagG), E(G), operation='+')
print(long_to_bytes(flag).decode())
```

Flag: `HarekazeCTF{MEI'5_70rp3d0_curv35_0n_311ip7ic}`

# Wilhelmina says <a name="wilhelmina-says"></a>

> Wilhelmina Braunschweig Ingenohl Friedeburg-san seems to want to tell something

```py
from Crypto.Util.number import getStrongPrime
import random

p = getStrongPrime(512)

with open("flag", "rb") as f:
  flag = int.from_bytes(f.read().strip(), "big")
  assert flag < p

t = flag.bit_length()
n = 5
k = 350

xs = [random.randint(2, p-1) for _ in range(n)]
ys = [x * flag % p for x in xs]
zs = [(y >> k) << k for y in ys]

print(f"{t=}")
print(f"{p=}")
print(f"{xs=}")
print(f"{zs=}")
```

```
t=311
p=10701453001723144480344017475825280248565900288828152690457881444597242894870175164568287850873496224666625464545640813032441546675898034617104256657175267
xs=[7891715755203660117196369138472423229419020799191062958462005957463124286065649164907374481781616021913252775381280072995656653443562728864428126093569737, 9961822260223825094912294780924343607768701240693646876708240325173173602886703232031542013590849453155723572635788526544113459131922826531325041302264965, 7554718666604482801859172289797064180343475598227680083039693492470379257725537783866346225587960481867556270277348918476304196755680361942599070096169454, 5460028735981422173260270143720425600672799255277275131842637821512408249661961734712595647644410959201308881934659222154413079105304697473190038457627041, 8621985577188280037674685081403657940857632446535799029971852830016634247561494048833624108644207879293891655636627384416153576622892618587617669199231771]
zs=[2445678981428533875266395719064486897322607935804981139297064047499983860197487043744531294747013763946234499465983314356438694756078915278742591478169600, 6687262023290381303903301700938596216218657180198116459210103464914665663217490218525920847803014050091904359944827298080739698457116239163607201903280128, 9144515139738671257281335253441395780954695458291758900110092599410878434836587336752247733779617485272269820837813132894795262162555273673307500761317376, 7005359236736263649027110410188576532095684249796929034336135801107965605961711614006159825405033239188458945408990893269975105260656611838449490684018688, 4638291797440604671051855904609667375394026160401800326727058461541969151082727684535417653507524951373254537356784859777006179731400955193335900924805120]
```

## Solution

To solve this challenge, you need to recognise that it is an instance of the hidden number problem. The HNP can be stated as follows:

Let $p$ be a prime and $d \in \mathbb{F}_p$ an unknown integer. Recover $d$ given pairs of integers $\{ (t_i, a_i) \}_{i=1}^m \}$ such that

$$
k_i - t_i d - a_i \equiv 0 \pmod p
$$

where the $k_i$ are unknown and $|k_i| < B$ for some $B < p$.

We can solve this problem in certain situations using lattice techniques.

Let $f$ denote the flag as an integer and let $x_i, y_i$ and $z_i$ be the elements of `xs`, `ys` and `zs` respectively. In the challenge, we have

$$
\begin{aligned}
    y_i &\equiv x_i f \pmod p \\
        &\equiv z_i + k_i \pmod p \qquad \text{for small $k_i$}
\end{aligned}
$$

Therefore,

$$
k_i - x_i f - (-z_i) \equiv 0 \pmod p
$$

and this is almost identical to the hidden number problem setting described above.

To see how we recover the value of $f$, consider the lattice generated by the rows of the matrix

$$
M =
\begin{bmatrix}
p  \\
  & p \\
  &   & \ddots \\
  &   &   &   p \\
x_0 & x_1 & \cdots & x_m & B/p \\
-z_0 & -z_1 & \cdots & -z_m & & B
\end{bmatrix}
$$

We will perform some lattice magic to find the smallest vector. Notice that the vector

$$
(k_1, k_2, \ldots, k_m, Bf/p, B)
$$

is a short vector (since the $k_i$ are "small") that is in this lattice; the linear combination is $f$ times the 2nd last row (the $x_i$ row), plus the last row, and then subtracting appropriate multiples of the $p$-rows. We see that the secret value $f$ will be in the 2nd last entry of the shortest vector, so we've recovered the flag!

```py
from Crypto.Util.number import long_to_bytes

exec(open('./distfiles/output.txt').read())
n = 5
B = 2^t

M = Matrix.diagonal(QQ, [p]*n)
M = M.stack(vector(xs))
M = M.stack(vector([-z for z in zs]))
M = M.augment(vector([0]*n + [B/p, 0]))
M = M.augment(vector([0]*n + [0, B]))
M = M.dense_matrix()
M = M.LLL()

for i in range(n+2):
    if M[i][-1] == B:
        f = M[i][-2]*p/B % p
        print(long_to_bytes(f).decode())
```

Flag: `HarekazeCTF{H0chmu7_k0mm7_v0r_d3m_F411}`
