---
path: /posts/2020-08-05-inctf-2020-writeups
title: InCTF 2020 Writeups
date: 2020-08-05
tags: ctf,infosec,writeup,crypto
---

# DLPoly (Crypto)

> RSA is easy. DLP is hard.

`out.txt`:

```
sage: p
35201
sage: len(flag)
14
sage: X = int.from_bytes(  flag.strip(b'inctf{').strip(b'}') ,  'big')
sage: n
n = 1629*x^256 + 25086*x^255 + 32366*x^254 + 21665*x^253 + 24571*x^252 + 20588*x^251 + 17474*x^250 + 30654*x^249 + 31322*x^248 + 23385*x^247 + 14049*x^246 + 27853*x^245 + 18189*x^244 + 33130*x^243 + 29218*x^242 + 3412*x^241 + 28875*x^240 + 1550*x^239 + 15231*x^238 + 32794*x^237 + 8541*x^236 + 23025*x^235 + 21145*x^234 + 11858*x^233 + 34388*x^232 + 21092*x^231 + 22355*x^230 + 1768*x^229 + 5868*x^228 + 1502*x^227 + 30644*x^226 + 24646*x^225 + 32356*x^224 + 27350*x^223 + 34810*x^222 + 27676*x^221 + 24351*x^220 + 9218*x^219 + 27072*x^218 + 21176*x^217 + 2139*x^216 + 8244*x^215 + 1887*x^214 + 3854*x^213 + 24362*x^212 + 10981*x^211 + 14237*x^210 + 28663*x^209 + 32272*x^208 + 29911*x^207 + 13575*x^206 + 15955*x^205 + 5367*x^204 + 34844*x^203 + 15036*x^202 + 7662*x^201 + 16816*x^200 + 1051*x^199 + 16540*x^198 + 17738*x^197 + 10212*x^196 + 4180*x^195 + 33126*x^194 + 13014*x^193 + 16584*x^192 + 10139*x^191 + 27520*x^190 + 116*x^189 + 28199*x^188 + 31755*x^187 + 10917*x^186 + 28271*x^185 + 1152*x^184 + 6118*x^183 + 27171*x^182 + 14265*x^181 + 905*x^180 + 13776*x^179 + 854*x^178 + 5397*x^177 + 14898*x^176 + 1388*x^175 + 14058*x^174 + 6871*x^173 + 13508*x^172 + 3102*x^171 + 20438*x^170 + 29122*x^169 + 17072*x^168 + 23021*x^167 + 29879*x^166 + 28424*x^165 + 8616*x^164 + 21771*x^163 + 31878*x^162 + 33793*x^161 + 9238*x^160 + 23751*x^159 + 24157*x^158 + 17665*x^157 + 34015*x^156 + 9925*x^155 + 2981*x^154 + 24715*x^153 + 13223*x^152 + 1492*x^151 + 7548*x^150 + 13335*x^149 + 24773*x^148 + 15147*x^147 + 25234*x^146 + 24394*x^145 + 27742*x^144 + 29033*x^143 + 10247*x^142 + 22010*x^141 + 18634*x^140 + 27877*x^139 + 27754*x^138 + 13972*x^137 + 31376*x^136 + 17211*x^135 + 21233*x^134 + 5378*x^133 + 27022*x^132 + 5107*x^131 + 15833*x^130 + 27650*x^129 + 26776*x^128 + 7420*x^127 + 20235*x^126 + 2767*x^125 + 2708*x^124 + 31540*x^123 + 16736*x^122 + 30955*x^121 + 14959*x^120 + 13171*x^119 + 5450*x^118 + 20204*x^117 + 18833*x^116 + 33989*x^115 + 25970*x^114 + 767*x^113 + 16400*x^112 + 34931*x^111 + 7923*x^110 + 33965*x^109 + 12199*x^108 + 11788*x^107 + 19343*x^106 + 33039*x^105 + 13476*x^104 + 15822*x^103 + 20921*x^102 + 25100*x^101 + 9771*x^100 + 5272*x^99 + 34002*x^98 + 16026*x^97 + 23104*x^96 + 33331*x^95 + 11944*x^94 + 5428*x^93 + 11838*x^92 + 30854*x^91 + 18595*x^90 + 5226*x^89 + 23614*x^88 + 5611*x^87 + 34572*x^86 + 17035*x^85 + 16199*x^84 + 26755*x^83 + 10270*x^82 + 25206*x^81 + 30800*x^80 + 21714*x^79 + 2088*x^78 + 3785*x^77 + 9626*x^76 + 25706*x^75 + 24807*x^74 + 31605*x^73 + 5292*x^72 + 17836*x^71 + 32529*x^70 + 33088*x^69 + 16369*x^68 + 18195*x^67 + 22227*x^66 + 8839*x^65 + 27975*x^64 + 10464*x^63 + 29788*x^62 + 15770*x^61 + 31095*x^60 + 276*x^59 + 25968*x^58 + 14891*x^57 + 23490*x^56 + 34563*x^55 + 29778*x^54 + 26719*x^53 + 28613*x^52 + 1633*x^51 + 28335*x^50 + 18278*x^49 + 33901*x^48 + 13451*x^47 + 30759*x^46 + 19192*x^45 + 31002*x^44 + 11733*x^43 + 29274*x^42 + 11756*x^41 + 6880*x^40 + 11492*x^39 + 7151*x^38 + 28624*x^37 + 29566*x^36 + 33986*x^35 + 5726*x^34 + 5040*x^33 + 14730*x^32 + 7443*x^31 + 12168*x^30 + 24201*x^29 + 20390*x^28 + 15087*x^27 + 18193*x^26 + 19798*x^25 + 32514*x^24 + 25252*x^23 + 15090*x^22 + 2653*x^21 + 29310*x^20 + 4037*x^19 + 6440*x^18 + 16789*x^17 + 1891*x^16 + 20592*x^15 + 11890*x^14 + 25769*x^13 + 29259*x^12 + 23814*x^11 + 17565*x^10 + 16797*x^9 + 34151*x^8 + 20893*x^7 + 2807*x^6 + 209*x^5 + 3217*x^4 + 8801*x^3 + 21964*x^2 + 16286*x + 12050
sage: g
x
sage: g^X
c = 10254*x^255 + 11436*x^254 + 9453*x^253 + 31783*x^252 + 22103*x^251 + 10097*x^250 + 28892*x^249 + 18508*x^248 + 22160*x^247 + 26375*x^246 + 3876*x^245 + 19858*x^244 + 30728*x^243 + 7847*x^242 + 16954*x^241 + 3306*x^240 + 13208*x^239 + 25886*x^238 + 33685*x^237 + 6481*x^236 + 12387*x^235 + 16989*x^234 + 32301*x^233 + 3069*x^232 + 1062*x^231 + 30500*x^230 + 7726*x^229 + 5137*x^228 + 10962*x^227 + 10406*x^226 + 22108*x^225 + 21887*x^224 + 739*x^223 + 27363*x^222 + 5715*x^221 + 8176*x^220 + 32398*x^219 + 33238*x^218 + 28151*x^217 + 18812*x^216 + 24615*x^215 + 8245*x^214 + 9730*x^213 + 8071*x^212 + 5590*x^211 + 21532*x^210 + 5962*x^209 + 17369*x^208 + 25626*x^207 + 14284*x^206 + 32492*x^205 + 3944*x^204 + 5227*x^203 + 30264*x^202 + 17098*x^201 + 28516*x^200 + 19180*x^199 + 31133*x^198 + 6217*x^197 + 29652*x^196 + 23061*x^195 + 22336*x^194 + 7848*x^193 + 15686*x^192 + 14763*x^191 + 27394*x^190 + 26349*x^189 + 3586*x^188 + 13954*x^187 + 12979*x^186 + 1909*x^185 + 506*x^184 + 18147*x^183 + 12126*x^182 + 8258*x^181 + 32944*x^180 + 11947*x^179 + 1354*x^178 + 33656*x^177 + 12395*x^176 + 14442*x^175 + 8301*x^174 + 4409*x^173 + 28252*x^172 + 29872*x^171 + 14252*x^170 + 2279*x^169 + 6317*x^168 + 31734*x^167 + 19036*x^166 + 520*x^165 + 34967*x^164 + 15096*x^163 + 20173*x^162 + 18962*x^161 + 28622*x^160 + 9961*x^159 + 18600*x^158 + 4794*x^157 + 33233*x^156 + 23874*x^155 + 26462*x^154 + 17088*x^153 + 11202*x^152 + 11392*x^151 + 16258*x^150 + 19460*x^149 + 17784*x^148 + 28458*x^147 + 817*x^146 + 25362*x^145 + 35096*x^144 + 3283*x^143 + 6551*x^142 + 30282*x^141 + 1134*x^140 + 29704*x^139 + 12388*x^138 + 20847*x^137 + 23240*x^136 + 25554*x^135 + 19687*x^134 + 22021*x^133 + 33659*x^132 + 19105*x^131 + 15422*x^130 + 32550*x^129 + 20712*x^128 + 11862*x^127 + 31185*x^126 + 9245*x^125 + 20218*x^124 + 18357*x^123 + 12809*x^122 + 20336*x^121 + 5247*x^120 + 6737*x^119 + 15970*x^118 + 14986*x^117 + 13437*x^116 + 8582*x^115 + 35005*x^114 + 14125*x^113 + 1110*x^112 + 11888*x^111 + 28756*x^110 + 11610*x^109 + 10241*x^108 + 13301*x^107 + 10052*x^106 + 3501*x^105 + 33176*x^104 + 12987*x^103 + 27504*x^102 + 21903*x^101 + 16653*x^100 + 12466*x^99 + 33281*x^98 + 360*x^97 + 26611*x^96 + 8066*x^95 + 1528*x^94 + 34974*x^93 + 16606*x^92 + 6724*x^91 + 18933*x^90 + 6703*x^89 + 6011*x^88 + 12647*x^87 + 32169*x^86 + 27545*x^85 + 18417*x^84 + 31199*x^83 + 17400*x^82 + 23798*x^81 + 16555*x^80 + 23009*x^79 + 1904*x^78 + 4962*x^77 + 1390*x^76 + 8141*x^75 + 25010*x^74 + 33199*x^73 + 19059*x^72 + 23473*x^71 + 14324*x^70 + 30136*x^69 + 15298*x^68 + 29677*x^67 + 33907*x^66 + 2250*x^65 + 34933*x^64 + 11261*x^63 + 22789*x^62 + 3652*x^61 + 15401*x^60 + 8978*x^59 + 32965*x^58 + 2505*x^57 + 17018*x^56 + 33296*x^55 + 27680*x^54 + 6679*x^53 + 24625*x^52 + 28932*x^51 + 789*x^50 + 10745*x^49 + 15681*x^48 + 14757*x^47 + 8233*x^46 + 15427*x^45 + 10112*x^44 + 30124*x^43 + 3701*x^42 + 31048*x^41 + 29692*x^40 + 2865*x^39 + 9066*x^38 + 20493*x^37 + 25607*x^36 + 115*x^35 + 9724*x^34 + 20716*x^33 + 19260*x^32 + 19536*x^31 + 6311*x^30 + 4672*x^29 + 27315*x^28 + 12186*x^27 + 17786*x^26 + 7341*x^25 + 4276*x^24 + 9217*x^23 + 6637*x^22 + 18711*x^21 + 19348*x^20 + 14022*x^19 + 30518*x^18 + 10550*x^17 + 19146*x^16 + 2430*x^15 + 25237*x^14 + 34375*x^13 + 2497*x^12 + 35085*x^11 + 8261*x^10 + 3388*x^9 + 26236*x^8 + 14902*x^7 + 14487*x^6 + 24280*x^5 + 11078*x^4 + 7380*x^3 + 24669*x^2 + 549*x + 1468
```

## Solution

We are given `x^{flag} mod n` where `n` is a polynomial in $\mathbb{F}_{35201}[x]$. The task is to solve the DLP in the quotient ring of polynomials in $\mathbb{F}_{35201}[x]$ by the ideal $n$ consisting of multiples of the polynomial $n$. This is denoted as $\mathbb{F}_{35201}[x]/\langle n\rangle$. Let's call this quotient ring $Q$. Sage has built in discrete log functions that are totally generic, but polynomial rings don't have an `.order()` method so we have to compute it ourselves. The order of a ring (or group) is the number of elements in it. Note that we are interested in the multiplication operation, so the elements we consider in the set are only those with multiplicative inverse elements (i.e. elements that are coprime with the modulus).

**Theorem:** Let $R = \mathbb{F}_p[x]/\langle N(x) \rangle$ for prime $p$ and $N(x) = P_1(x)P_2(x)\cdots P_r(x)$ where $P_i(x)$ are irreducible polynomials in $\mathbb{F}_p[x]$. Then, the order of $R$ is $\prod_{i = 1}^r ( p^{\deg(P_i)} - 1 )$.

**Proof:** We start by computing the total number of polynomials in $R$. That is, the number of polynomials with coefficients in $\mathbb{F}_p$ whose degree is less than $\deg(N)$. These polynomials can be written as

$$
\sum_{i=0}^{\deg(N)-1} k_i x^i
$$

There are $\deg(N)$ coefficients, and each coefficient can take up to $p$ values, so there are $p^{\deg(N)}$ possible polynomials.

Next, we exclude the polynomials that are not invertible. These are polynomials that share a factor with $N(x)$, that is, multiples of $P_i(x)$. We use the [inclusion-exclusion principle](https://en.wikipedia.org/wiki/Inclusion%E2%80%93exclusion_principle) to obtain an expression for the number of polynomials that are not coprime to $N(x)$. Let $A_i$ be the subset of polynomials in $R$ that are multiples of $P_i$. Then

$$
\left | \bigcup_{i=1}^r A_i \right | = \sum_{i=1}^r | A_i | - \sum_{1 \leq i < j \leq r} | A_i \cap A_j | + \sum_{1 \leq i < j < k \leq r} | A_i \cap A_j \cap A_k | - \cdots + (-1)^{r} | A_1 \cap \cdots \cap A_r |
$$

Consider $A_i$. The polynomials in $A_i$ have the form $Q(x)P_i(x)$ where $Q(x)$ is of degree $\deg(N) - \deg(P_i)$. Therefore $|A_i| = p^{\deg(N) - \deg(P_i)}$.

Next, consider $A_i \cap A_j$ where $i < j$. The polynomials in $A_i \cap A_j$ have the form $Q(x)P_i(x)P_j(x)$ where $Q(x)$ is of degree $\deg(N) - \deg(P_i) - \deg(P_j)$. Therefore $|A_i \cap A_j| = p^{\deg(N) - \deg(P_i) - \deg(P_j)}$.

In general, $| A_{i_1} \cap \cdots \cap A_{i_k} | = p^{\deg(N) - \deg(P_{i_1}) - \cdots - \deg(P_{i_k})}$ for $1 \leq i_1 < \cdots < i_k \leq r$.

So

$$
\begin{aligned} \#R &= p^{\deg(N) - 1} - \left | \bigcup_{i=1}^r A_i \right | \\ &= p^{\deg(P_1) + \cdots + \deg{P_r} - 1} - p^{\deg(P_2) + \cdots + \deg(P_r)} - p^{\deg(P_1) + \deg(P_3) + \cdots + \deg(P_r)} - \cdots \\ &\hspace{0.3in} + p^{\deg(P_3) + \cdots + \deg(P_r)} + p^{\deg(P_2) + \deg(P_4) + \cdots + \deg(P_r)} + \cdots + (-1)^{r} \\ &= (p^{\deg(P_1)} - 1)(p^{\deg(P_2)} - 1) \cdots (p^{\deg(P_r)} - 1) \\ &= \prod_{i=1}^r (p^{\deg(P_i)} - 1) \end{aligned}
$$

### Solving the challenge

Since $n(x)$ is square free, we can compute the order of $Q$ using the above theorem. Doing so gives us the following extremely large integer:

```
828095283078365821035906712584313613267259374081020419504932352155659177459160341091828947167865033167221905108312125495452745499324882907347920414906104292582906330915099958576679626146770228352240585630930139661045176562591142477774139672383036818326923547793197940683916579620016589545313412510178382062940020658088409985109520664200101047441395894492801337264842708432166493291241118107917027085612583904881045016599048631676023448658571574675694109595884112047534414651568829566811446147026894559715306435293623664371754538446523791290736118660976615503028557578911645115805550332275939674586196923036628855241080783528653557249828462947924249198381038178461485336950387183600669876163630183894738670160739263190797639665069711057118752501596719589043439771930596882669052368132928844025392834319313873873036523980321058917024339536530832567697942263196837532182794282926503255463388996348655925894641051753889126844537253605132148449110651332484156106043375966561712868991682036168081784393896390881977942489907297854619599492425911383384237229610389703619707077306718091171227238400000000000000000000000000000000000000000000000000000000000000000000000000000
```

Fortunately, the order has many small factors:

```
2^208 * 3^27 * 5^77 * 7^2 * 11^26 * 13 * 31^25 * 41^25 * 241 * 271 * 1291^25 * 5867^26 * 6781^25 * 18973 * 648391 * 62904731^25 * 595306331^25 * 1131568001^25
```

so we will be able to solve the DLP using Pohlig-Hellman.

Since the exponent is at most $2^{56}$, we only need to take factors such that their product is greater than $2^{56}$. Practically, this can be a bit smaller as we know the secret encodes ascii values which are no where near 255. Taking the factors `[13, 241, 271, 18973, 648391]` gives a product of about `2^54` which should be good enough. Since these numbers are very small, solving DLP in subgroups of their order is very easy and could even be done using a pure bruteforce algorithm. The solution script simply implements a simplified version of [Pohlig-Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm).

**Solve script:**

```python
p = 35201
n = ...
c = ...

P.<x> = PolynomialRing(GF(p))
n = P(n)
g = x
Q.<x> = P.quotient(n)
h = Q(c)
order = prod(p^(d.degree()) - 1 for d,_ in n.factor())
print('[+] order:', order)
print('[*] factors:', order.factor())
factors = [13,241,271,18973,648391]
K = []
for f in factors:
    qi = order//f
    Pi = x^qi
    Qi = h^qi
    K.append(discrete_log(Qi, Pi, ord=f))
print(K)
flag = crt(K, factors)
print(bytes.fromhex(hex(flag)[2:]))
```

Flag: `inctf{bingo!}`

---

References: http://www.diva-portal.se/smash/get/diva2:823505/FULLTEXT01.pdf
