= yaml =
title: HackCon 2019 Writeups
slug: hackcon-2019-writeups
date: 24/08/2019
tags: ctf,infosec,writeup,crypto
= yaml =

#### Challenges:
  - Crypto
    - OTP
    - Noki
    - Ez Pz
    - Time Travel

# Crypto

# OTP

## Crypto - 100 points

> hackerman is so dank that he decided to play around with OTPs.
> he did the following:
> message1 ^ key = cipher1
> message2 ^ key = cipher2
> 
> He gives you cipher1 and cipher2 and challenges you to find the concatenation of messages 1 and 2.
> Are you dank enough to find this?
> Oh and also, 'meme' is so popular that hackerman used the word in both his messages.
> cipher1 is '\x05F\x17\x12\x14\x18\x01\x0c\x0b4'
> cipher2 is '>\x1f\x00\x14\n\x08\x07Q\n\x0e'
> Both without quotes

---

### Solution

We know the flag format is `d4rk{XXXX}c0de`. The two ciphertexts given both have length 10, so the flag will be a total of 20 characters. Since the `d4rk{` and `}c0de` bits are both of length 5, the actual contents is only of length 10.

We begin by XORing the two ciphertexts to get the XOR, `x` of the two messages:

$$\begin{aligned} c_1 \oplus c_2 &= (m_1 \oplus k) \oplus (m2 \oplus k) \cr &= (m_1 \oplus m_2) \oplus (k \oplus k) \cr &= (m_1 \oplus m_2) \oplus  0 \cr &= m_1 \oplus m_2 \end{aligned}$$

So if we know the contents of either message, we can use that to extract the contents of the other. Since there are only 10 bytes, we can try each of the 7 offsets easily by hand. We find straightaway that XORing `x[1:5]` with `b'meme'` gives us `b'4rk{`. This tells us that the word `meme` is in the 2nd position of the second message. From this we fill in what we know of each message: `m1 = x4rk{xxxxx` `m2 = xmemexxxxx`. Since the flag is the concatenation of `m1` and `m2`, we are safe to assume even further: `m1 = d4rk{xxxxx` `m2 = xmeme}c0de`. Knowledge that the very first byte of the flag is `b'd'` allows us to obtain the first byte of `m2`: precisely, the first byte of `m2` is `ord('d') ^ x[0] = '_'`, so we get the full second part of the flag: `_meme}c0de`. We can find the last half of the first part of the flag by XORing `x[-5:]` with `b'}c0de'`. Doing this and concatenating `m1` and `m2` gives us the full flag: `d4rk{meme__meme}c0de`.

---

# Noki

## Crypto - 198 points

> I was told Vigenère Cipher is secure as long as `length(key) == length(message)`. So I did just that!
> 
> Break this: g4iu{ocs_oaeiiamqqi_qk_moam!}e0gi

---

### Solution

It turns out that the key being used is the message. Since we don't know the plaintext, we simply bruteforce it (there are two possibile decryptions for each byte in the ciphertext). We print out the possibilities side by side so it is easy to determine what looks the most like the flag:

```python
from collections import defaultdict

alphabet = 'abcdefghijklmnopqrstuvwxyz'

def D(c, k, a=alphabet):
    return a[(a.index(c)-a.index(k))%len(a)]

same_key = defaultdict(list)
for l in alphabet:
    for k in alphabet:
        kouho = D(l, k)
        if kouho == k:
            same_key[l].append(k)

c = 'g4iu{ocs_oaeiiamqqi_qk_moam!}e0gi'
for l in c:
    if l not in alphabet:
        print(f'{l} | {l}')
        continue
    m1, m2 = same_key[l]
    print(f'{m1} | {m2}')
```

The output is:

```
d | q
4 | 4
e | r
k | x
{ | {
h | u
b | o
j | w
_ | _
h | u
a | n
c | p
e | r
e | r
a | n
g | t
i | v
i | v
e | r
_ | _
i | v
f | s
_ | _
g | t
h | u
a | n
g | t
! | !
} | }
c | p
0 | 0
d | q
e | r
```

Flag: `d4rk{how_uncreative_is_that!}c0de`


[Read more about the Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)

---

# Ez Pz

## Crypto - 484 points

> easiest crypto points ever
>
> `nc 68.183.158.95 7777`

---

### Solution

Connecting to the service gives us an encrypted message with some other options:

```bash
Welcome to your local encryption decryption service John
On tonights menu --- 12365191986981076101047301370701570581285242722755908917452477513812917333235908372158179408832263741318846491080415172065838545904289980141610275604417957376065110402564156971200836754229931905081802770089611721313808973726863824696418951656946609543021504241467014047427697808677490304355825391582732585142263321488663694882470233212956187560486959249762884932265729798974327721628751815992060266204391519658533954549650088979483475917712772079800223442867519466099168383602073525487372612858592484677931513715424225401890124122712055965506816324533693708113819113841867934683163416565674304182472697147756571479875
1)Encrypt
2)Decrypt
3)Exit
```

We have an encryption/decryption oracle that will encrypt a message that we give it (in bytes) or decrypt a message (except for the given ciphertext).
We can play around with the service (ask it to encrypt b'\x01'...) to find out that it is RSA with `e = 0x10001`.

Because it will decrypt any message, we can ask it to decrypt $2^e \times c$ which will allow us to easily obtain the flag.

$$\begin{aligned} m^e &\equiv c \pmod n \cr \implies 2^em^e &\equiv 2^e c \pmod n \cr \implies (2m)^e &\equiv 2^e c \pmod n \end{aligned}$$

So upon decryption:

$$\begin{aligned} M &\equiv (2^ec)^d \pmod n \cr &\equiv 2^{ed}c^d \pmod n \cr &\equiv 2c^d \pmod n \end{aligned}$$

And therefore,

$$\begin{aligned} m &= \frac{M}{2} \cr &= \frac{1}{2}2c^d \mod n \cr &= c^d \mod n \end{aligned}$$

So we just divide the resulting decryption by 2 to obtain the flag.

Implementation:

```python
from Crypto.Util.number import *
from pwn import *
conn = remote('68.183.158.95', 7777)
initial_msg = conn.recvuntil('Exit\n').decode()
c = int(initial_msg.split('--- ')[1].split('\n1)Enc')[0])
conn.sendline('2')
conn.recvline()
conn.sendline(str(pow(2, 0x10001) * c))
d = conn.recvline()
decrypted = int(d.decode()[:-1])
m = decrypted//2
print(long_to_bytes(m))
```

Flag: `d4rk{th3_ch33si3st_m4th_p1zz4_f0r_d1nn3r!}c0de`

---

# Time Travel

## Crypto - 496 points

> Alpha is a n00b coder but also can time travel, we were somehow able intercept his space-time but we can't make any sense of it.

```python
from Crypto.Util import *
import gmpy
import random

def gcd(a,b): 
    if(b==0): 
        return a 
    return gcd(b,a%b)

def giveMeABigNumber():
	return random.randint(0,pow(10,1337))

def encode(x):
	s =''
	for i in str(x):
		s += str(dictionary[i])
	return int(s)

def g(x,e,N):
	t = 1
	i = 0
	while i != e:
		t *= x
		t %= N
		i += 1
	return t

def f(x,k,e,N):
	x = g(x,e,N)
	x *= k
	x %= N
	return x

def giveMeSomeGoodPrimes():
	primes = []
	while len(primes) != 255:
		x = number.getPrime(32)
		if len(str(x)) != 10:
			continue
		else:
			if x in primes:
				continue
			primes.append(x)
	while True:
		g = primes[0]
		phi = 1
		for i in primes:
			phi *= (i-1)
		if gcd(phi,sum(primes)) == 1:
			break
		else:
			primes.pop(0)
			while True:
				x = number.getPrime(32)
				if len(str(x)) != 10:
					continue
				else:
					if x in primes:
						continue
					primes.append(x)
					break			
	return primes

primes = giveMeSomeGoodPrimes()
primes.sort()

flag = 'd4rk{************REDACTED************}c0de'

diff_vec = []

for i in range(1,len(primes)):
	diff_vec.append(primes[i]-primes[i-1])

dictionary = {}

for i in range(255):
	dictionary[chr(i)] = primes[i]

e = sum(primes)
k = 0
N = 1
for i in range(len(primes)):
	k ^= primes[i]
	N *= primes[i]

enc = encode(flag)

myBigNumber = giveMeABigNumber()

i = 0

while i != (myBigNumber):
	enc = f(enc,k,e,N)
	i += 1

print (enc,k,e,N,diff_vec,myBigNumber)
```

```python
(3909562562549157082533103708441466612464633776440564899591138667013780029712864831795834170178552326412148054190539912173608873450789698245904097384050705528191693318428325947401715767532104809365237869635380171955155796846609309800015506642758431015925806740215584808112689224514577864676312819447278987732503322100862064190124254500116573510391047676341877592755428251594943049295766943219530799818985074248120637536276401470587578869222009781246901425687522250235813405641212501332983915805081175007154535917309469753907740745655991731861575476657687733835355556999046201270361822139140511466090752023289789025937698690196793233104311010835798623791540162086076830138048243150987374419876289632079844243605607740874470832725865787948382555812575341960955116906261804998300080085063796304408319416070364468764104686286911633019543981098682461652054717404453342849171427809063288913489003767129036594800462932925500607495763819769499796988777863237480295203228038044603286195650025636335941361500844332455782488780412199046979452391643746451457006427689989913994566197823884488985921877428093118772617480550450594546291889004276769486465528181626833450028121078886259851188420001803172134072396924778756605326077810618762951676825397342618660226022102146675727063433348441140323677534369947604723147503797297021642770955253284350851643082771269809432613915469480493454039828328472404807478174524786979624596796713846130137126982983481452043950619529315645805794046546510294178594742944961277510990272295729050743356505832049453951306080841433870458444036823766986293543286397188520064731528425837156905522768486159239014059984497897644615055735225808950926577088785563219335775815115733178408569402520148983698598855467771211154961538574274255167731206642614471741008883474284027391734554518978152360470312997145338228645604294837868948224227533661224787180288264585122170130997302425315728849821100603706309735088308324674749421803139018330763055692148878025049794325719951580189177358148186114659353196408956163833920888803970053268752459264395164548121763166654851828293738384757478525480930807686523979397236521194292635270790662328101523721748202651638018643017386830490040105799619238933159950533382793715804052488273559326610020091655170447114700201704643944045668070995479218836484318035118888838622871252305857424148670342627671808964273293684053666103123369868498465384505725313207143186249337055882383374700600L, 4276952879L, 825098699749L, 97073333323921920810872821614483773136652117900028078317118571237827871587948251360142299421913881234925823504979192680539639488597729720403744028149472398497783996679963447180529634506685970330696810112973188453085701137147174739788489577098780249238534029288870358773574406799664793337670806134157730679275600758664398426528506900162999414083824908802151126038642355422275587434716674625531493555183534792093179369576691033837462116271205209853071842134132968161773980205220960707744085514381302952534934699388296619110650254260856520085888948459147881293158363054411871491979844842590230946783537888328057787215753130727685883461850725337952641441419338372527153164604918191574434012976886747948973145228145896827506453547960175512785146410210814193592845690186917288644182980721982198381884396066778564126227102755942583796120158251571367601028450215611385152200666371129601299231516662667317498513304237867457756377111805758414662838451763323194200702822605418995985309412603227384081121349510580269095366278528289622754422633485605612529408910667623716089986972455676258850605139989534430427257222993360244691826860587328791296857331674442607603826190923247037816628952060391000338243085648485635372922999507469570075350754220027240539979139386556787215595784382271584488363678714038645279162161971066155839636316277911437567051598706526915644213080910939215833274314113649777285602426623977533257953535346671882787848235546985527628119297640114373386876946182239080143860794159488993748197329015991112620630076934034269678460112081439248362335738022687618744096254438845195481836189735917375233441653754904509564893114007244126799547215861571080382605290756367325502896917018040532475311002094092422133864458536257851073030855155854412728975297467595699406455307926553383242438194206193696655720968982469986570215363884921991198234519946252129512179200911105108365986830631785978162196145842226489399393445105935417286858667468882879595504438374018872679071490259684957276011261856328889093529669138704127279415305816044998371254290537666659241219895047707344501722618322780115885329718260460555556435349631956168786848840659992738689228687690310204041777988262818441228332726015120116580416267541338109327489948117068652368509902286251481368669833312251773172986788656991186839589709473615823059806398516791631025491734127392647055456105598325533212510279097293182773872593780900222659759452687020466104503356662271L, [8211052L, 23874516L, 11709752L, 1883404L, 67514L, 209664L, 1714878L, 14982552L, 14167212L, 2045518L, 1929498L, 12401628L, 5067894L, 7757400L, 5443506L, 10432412L, 5014644L, 1733236L, 8753334L, 8131310L, 4425628L, 2757288L, 24299942L, 5526426L, 10226614L, 6228608L, 2264112L, 12283650L, 1800888L, 6569934L, 2502324L, 3476644L, 6775020L, 1710032L, 6468096L, 6274L, 12545690L, 35297788L, 15042098L, 11169912L, 13632070L, 1353020L, 10416658L, 21322110L, 17842980L, 16405110L, 7466004L, 23464910L, 3146268L, 29875090L, 6408800L, 7672990L, 11010470L, 11197996L, 304884L, 5920182L, 20261090L, 1661070L, 9225556L, 5869878L, 6154146L, 1262504L, 5950264L, 1223658L, 13308252L, 7421702L, 13098670L, 5473386L, 31226732L, 6087690L, 33307606L, 10544310L, 8509070L, 12745462L, 251448L, 14805444L, 28058618L, 22197000L, 11324782L, 16477098L, 1910558L, 25599082L, 3487418L, 4898292L, 12307210L, 7341618L, 4881702L, 6371792L, 5476848L, 12337168L, 6607680L, 4390932L, 848580L, 4645680L, 641760L, 2172608L, 3118384L, 1120698L, 2024882L, 5282466L, 7698780L, 2929080L, 769654L, 19131368L, 3046882L, 1666410L, 4263368L, 2087250L, 5454880L, 4162464L, 4707476L, 5416230L, 2835738L, 4353292L, 15632762L, 6249486L, 3347652L, 272214L, 6860428L, 1562210L, 10217896L, 1172094L, 13666356L, 2764502L, 4349118L, 32958106L, 12632648L, 8200470L, 5269000L, 15155730L, 18296130L, 10022556L, 6170006L, 13749538L, 479276L, 6268810L, 11469716L, 1960486L, 593112L, 3093516L, 1074252L, 7571010L, 21934398L, 394686L, 3943884L, 1803590L, 10330686L, 13594684L, 604722L, 5934918L, 10581386L, 14962780L, 1925850L, 3934388L, 13413840L, 377218L, 11117844L, 4628034L, 4529994L, 1997918L, 4272082L, 4131386L, 17331970L, 2782982L, 11404072L, 818750L, 26651838L, 3051862L, 5169572L, 396028L, 1739768L, 29782L, 6957912L, 26508368L, 15379836L, 25714062L, 15445960L, 3935000L, 3462514L, 8996724L, 13845216L, 4449588L, 10332420L, 29296106L, 20448840L, 185764L, 2041008L, 2353664L, 12404274L, 1449870L, 770796L, 715098L, 4378606L, 910844L, 3916696L, 1997370L, 41502782L, 19740498L, 2681044L, 2518148L, 10123362L, 4810228L, 4349418L, 890982L, 10420892L, 10522906L, 15207566L, 14250798L, 134248L, 699278L, 22346506L, 695730L, 10780644L, 4089272L, 4016644L, 8501826L, 13063014L, 1188266L, 273472L, 23638326L, 3202764L, 3900918L, 9235422L, 2631330L, 14549780L, 1577506L, 12273956L, 237106L, 8188622L, 2546872L, 5410664L, 9315840L, 4708914L, 25212928L, 3593090L, 31308L, 31602550L, 5689740L, 6727946L, 3221280L, 505266L, 20208024L, 596400L, 8550490L, 26119248L, 13969688L, 2659174L, 395864L, 28862982L, 3423724L, 15734420L, 3578158L, 5809740L, 1894458L], 28813093165294957239494011100792223904827780737815938973204851068881415562562324592613417099906299823670854066152215369799307248534159111078720700354710300547410233966020018520847107129629353932119272690347718143659548531148044587991604452406833621788194705649039120054215657809570960170878422238296004330146134932296031846744386774196118773096680922553295601004518489139946639628288730662887728650376502874390082806070106281130762577891999103272039109006654420008962672717304822728710847952889645761335963787490964706752225172652335386657431891572507093237433060409975687853771074654179084412416670388851099883770828475357090924703507899619904432180516123154900584198303762738354396857706390243722810811221937347551802885371317085742392511601831136257442077728394467458407955139685058539777675588281216265411961526426258731242557101892400143156674735049015998765396526391707352818646109873666169478839368356677780913895151260214538662237258762654875923316038250394225469039004343719182814931781089801458747976056705363516887506526545185133317017283872682126145291097118421143068137914100096504200476594682992202425634182287704946118986588030115779601686861756108085466161532558382536048833508782710884181703969566382587454879374734272345617855288407857652825736393925800889786176067120911339887439019174499245962426379483291681991299526L)
```

---

### Solution

We begin by analysing the functions.

`giveMeABigNumber` does exactly what it says.

`g` is simply `pow` implemented iteratively.

`f` is equivalent to: $f(x, k, e, N) \equiv kx^e \pmod n$

`giveMeSomeGoodPrimes` generates a list of 255 primes such that, if `N` is the product of all the primes, then the totient of `N` is coprime to the sum of the primes. These primes will be used to replace bytes.

We're given the difference between adjacent primes in the `diff_vec` variable. We're also given the sum of all primes in the `e` variable. We will need to know the primes to determine $\phi(N)$ and also to decode the flag. Here is how we go about recovering the primes:

#### Recovering the primes

(Note there are 255 primes, so there are 254 elements in the `diff_vec` list)

Firstly, we know $e = \sum_{i=0}^{254}p_i$ and $d_i = p_{i+1} - p_i$ for all $i \in \{0, 1, 2, ..., 254\}$

Notice that $\sum_{i=j}^k d_i = p_{k+1} - p_j$

So, $e + \sum_{j=0}^{253}\sum_{i=j}^{253} d_i = 254p_{254}$ which gives us the value of the last prime, $p_{254}$.

Similarly, $(e - p_{254}) + \sum_{j=0}^{252}\sum_{i=j}^{252}d_i = 253p_{253}$ which gives us the value of $p_{253}$.

In general, we have $\sum_{i=0}^{n}p_i + \sum_{j=0}^{n-1}\sum_{i=j}^{n-1}d_i = np_n$. So we can easily recover the primes:

```python
def recover_primes(e, diff_vec):
    primes = []
    # start by recovering prime 0xff
    # then subtract that and recover prime 0xfe...
    def recover_last_prime(prime_sums, diff_vec):
        for i in range(len(diff_vec)):
            prime_sums += sum(diff_vec[i:]) 
        return prime_sums // (len(diff_vec) + 1)
    for i in range(0xff):
        p = recover_last_prime(e, diff_vec)
        primes.append(p)
        e -= p
        diff_vec = diff_vec[:-1]
    return sorted(primes)
```

#### Analysis of encryption

Next, we take a look at the while loop:

```python
myBigNumber = giveMeABigNumber()
i = 0
while i != (myBigNumber):
	enc = f(enc,k,e,N)
	i += 1
```

`f` is repeatedly applied to `enc`, and this happens for an extremely large number of iterations. We won't be able to reverse each iteration with a loop as that would take too long. Instead, we look to what `f` actually does.

$f(x, k, e, N) = kx^e \pmod N$

For brevity, we will write $f(x) = f(x,k,e,N) = kx^e \pmod N$ since $k$, $e$ and $N$ are constants.

Then,

$$f(f(x)) = f(kx^e \mod N) \equiv k(kx^e)^e \pmod N \equiv k^{e+1}x^{e^2} \pmod N$$

Furthermore,

$$f(f(f(x))) = f(k^{e+1}x^{e^2} \mod N) \equiv k(k^{e+1}x^{e^2})^e \pmod N \equiv k^{e^2+e+1}x^{e^3} \pmod N$$

In general, we have

$$f_n(x) \equiv k^{e^{n-1}+e^{n-2}+\dots+1}x^{e^n} \pmod N$$

where $f_n$ denotes $n$ recursive applications of $f$.

Because `myBigNumber` is so massively large, we must find a way to efficiently compute the $k$ term so that we can find its inverse. Obtaining $x$ given $x^{e^n} \mod N$ is trivial as we know $\phi(N)$.

For now, we will worry about efficiently computing the $k$ term with the sum in its exponent.

#### Efficiently computing $k^{e^{n-1} + e^{n-2} + \dots + 1}$

It turns out we can compute the geometric series in logarithmic time using the fact:

$$1 + a + a^2 + \dots + a^{2n+1} = (1 + a)(1 + (a^2) + (a^2)^2 + \dots + (a^2)^{n})$$

That is, if the highest exponent is odd, we can reduce the sum to a product of something we can easily compute $(1+a)$ and another geometric series with the highest exponent being halved.

If the highest exponent is even, then we factor out $a$ to get an expression with a geometric series whose highest exponent is odd. i.e.:

$$1 + a + a^2 + \dots + a^{2n} = 1 + a(1 + a + a^2 + \dots + a^{2n-1})$$

The base case for this recursive procedure will occur when the highest exponent is $0$, in which case, we simply return $1$.

Using this, along with the fact that we can take sums and products modulo $N$ and the overall result will still be correct modulo $N$, we write the function:

```python
def gp_sum(a, t, N):
    if t == 0: return 1
    if t&1: return (((1+a)%N)*gp_sum((a*a)%N,(t-1)//2,N))%N
    return (1+(a*gp_sum(a,t-1,N))%N)%N
```

Now, we use [Euler's theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem), which states
$$x \equiv y \pmod{\phi(n)} \implies a^x \equiv a^y \pmod n$$
with $\gcd(a,n) = 1$

In particular, if we let $s = e^{n-1} + e^{n-2} + \dots + 1 \mod \phi(N)$, then

$$s \equiv e^{n-1} + e^{n-2} + \dots + 1 \pmod{\phi(N)}$$

and so

$$k^s \equiv k^{e^{n-1}+e^{n-2}+\dots+1} \pmod N$$

#### Obtaining $x$

We have now reduce the recursively applied $f$ down to the expression $f_n(x) \equiv k^s x^{e^n} \pmod N$ where $k^s$ can be easily computed. We can then calculate the modular inverse of $k^s$ with respect to the modulus $N$, and multiply $f_n(x)$ by that to get $x^{e^n}$ on its own:

In particular, with $d_k$ such that $d_k k^s \equiv 1 \pmod N$, we compute:

$$\begin{aligned} f_n(x) d_k &\equiv d_kk^sx^{e^n} \pmod N \cr &\equiv x^{e^n} \pmod N \end{aligned}$$

And to get $x$ on its own, we compute $d$ such that $d e^n \equiv 1 \pmod{\phi(N)}$ (i.e. the modular inverse of $e^n$ with respect to the modulus $\phi(N)$). We then raise our express to this power to obtain $x$:

$$ (f_n(x)d_k)^d \equiv (x^{e^n})^d \pmod N \equiv x \pmod N$$

All that's left is to decode the value.

#### Decoding $x$

$x$ will be a number that was formed by taking the string representations of the `primes` (corresponding the each byte) and concatenating them. Since each prime is 32 bits, we expect the string length of $x$ to be a multiple of 10. So we simply break $x$ up into strings of 10 digits (which should be a prime number in the `primes` list), and inverse map them back to the character that they represent.

#### Implementation

```python
from vals import enc,k,e,N,diff_vec,myBigNumber
from Crypto.Util.number import isPrime, GCD
from gmpy2 import invert
from sys import setrecursionlimit
setrecursionlimit(133337)

def dec(x, d):
    out = ''
    for i in range(0, len(x), 10):
        out += d[int(x[i:i+10])]
    return out

def gp_sum(a, t, N):
    if t == 0: return 1
    if t&1: return (((1+a)%N)*gp_sum((a*a)%N,(t-1)//2,N))%N
    return (1+(a*gp_sum(a,t-1,N))%N)%N

def fBinv(c, k, e, N, B, phi):
    dk = invert(pow(k, gp_sum(e, B-1, phi), N), N)
    m = (c*dk)%N
    d = invert(pow(e, B, phi), phi)
    return pow(m, d, N)

def recover_primes(e, diff_vec):
    primes = []
    # start by recovering prime 0xff
    # then subtract that and recover prime 0xfe...
    def recover_last_prime(prime_sums, diff_vec):
        for i in range(len(diff_vec)):
            prime_sums += sum(diff_vec[i:]) 
        return prime_sums // (len(diff_vec) + 1)
    for i in range(0xff):
        p = recover_last_prime(e, diff_vec)
        primes.append(p)
        e -= p
        diff_vec = diff_vec[:-1]
    return sorted(primes)

primes = recover_primes(e, diff_vec)

assert len(primes) == 0xff
phi = 1
for p in primes:
    assert isPrime(p)
    phi *= (p-1)
assert GCD(sum(primes), phi) == 1

dictionary = {}
for i in range(255):
    dictionary[primes[i]] = chr(i)

m = fBinv(enc, k, e, N, myBigNumber, phi)
print(dec(str(m), dictionary))
```

Flag: `d4rk{d1d_y0u_t1m3_tr4v3l_0r_u53d_m4th?!}c0de`

---
