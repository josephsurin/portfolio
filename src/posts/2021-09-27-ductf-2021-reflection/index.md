---
path: /posts/2021-09-27-ductf-2021-reflection
title: DownUnderCTF 2021 Reflection
date: 2021-09-27
tags: ductf
---

The second edition of DownUnderCTF successfully finished over the weekend with a turnout of over 4000 players and 2100 teams. The entire team put a massive effort into making this CTF and it was great working with them. We had a total of 69 challenges of which I wrote 17 including crypto, rev, and pwn tasks. I'll write about some thoughts on my own tasks, as well as some general feedback, how I felt while preparing for the CTF, and what it was like during the CTF.

All of the challenge files and writeups can be found [here](https://github.com/DownUnderCTF/Challenges_2021_Public).

# Background

The first edition of DUCTF ran in 2020. Max gathered a bunch of people interested in volunteering their time to run a CTF from some infosec societies around Australia and we started doing things. The 2020 CTF ran in September, so we only had around 3 months to prepare. It wasn't a lot of time, but we managed to put something together and ran a pretty successful first CTF.

Following that, we had a meeting and most people were still interested to run the CTF next year, so here we are. Given that our target was roughly around the same time (which we had a lot of good feedback as it's a holiday week for most schools/unis), we had a full year to prepare. Obviously, with most of us being uni students, there was a lot of procrastination and leaving things til the last minute. Regardless, throughout the year, people started bouncing challenge ideas, the marketing team worked on contacting sponsors and the infra team did _the infra stuff_.

A lot goes into holding a competition on this scale. My name appeared on a lot of the challenges, so it might seem like I did the most, but that couldn't be further from the truth. Without our amazing marketing team making graphics, writing emails and tweets, chatting with CEOs, registering us as an incorporated association, etc. we wouldn't have had the reach we did nor the financial capability to even run the CTF. And our incredibly talented infrastructure team worked tirelessly to make sure everything went smoothly for both us challenge developers and all the players. I can't even begin to comprehend what they are saying half of the time, but they are wizards and we would be hopeless without them.

# Preparation

Since I am useless at writing English words and only barely know how to use Docker, I couldn't contribute much to the CTF other than writing challenges. I don't really have much to say about preparing challenges, but since people have asked how I come up with ideas and how I go about writing challenges, I'll try to recap how I came to write challenges for this year's CTF.

In general, playing a lot of CTFs helps for inspiration and also to get an idea of what people enjoy. Other than that, whenever I see something cool or randomly think of an idea, I write it down somewhere and continue to think about it and write down more stuff in the following days or weeks hoping it develops into something a bit more substantial.

For crypto challenges in particular, it helped quite a bit (in some ways..) that whenever I read a bit of math my brain would try and think how it could be turned into a CTF challenge. A lot of my ideas came from studying Algebra in my first semester and reading papers as well as reading discussions on the CryptoHack discord. Playing around with concepts and trying to implement attacks for no good reason was also pretty helpful and how I ended up writing 1337crypt v2.

I started writing the reversing and pwn challenges quite late because I realised that we probably weren't going to get many challenges in these categories since Faith has just been really busy, and we didn't have many people strong with rev. It was my first time writing challenges in these categories (though I had been trying to learn pwn for a few months) so I was a bit worried something would go wrong. My team mate and good friend [John](https://rwx.rip/) helped me a lot with learning pwn and some things we found when working through CTF challenges together was the inspiration for one of the challenges I wrote. Faith also provided some valuable QA for some of the pwn challenges which was helpful. For the reversing challenges, a lot of them sprouted from puzzle ideas which I just implemented in C and called it a rev challenge...

# During the CTF

We decided to use a ticket support system this year inspired by how well it worked for the Cybears at Bsides Canberra CTF earlier this year. This decision was both a blessing and a curse. We had overwhelmingly positive feedback for our support effort this year. We had almost 24/7 support available (shoutout to the night shift crew) and the ticket system made it easy for all of the admins to help out and see what issues people were having. We were a lot more lenient with hints and nudges this year for the easier challenges and we found that a lot more people were able to enjoy the CTF because of that.

We serviced over 1500 tickets with a team of around 10 to 15 staff which was no easy feat. At times I felt really overwhelmed by the amount of people DMing me and requesting my support in tickets and I felt bad that it took so long to respond to them. In my opinion, there were a lot of unnecessary support requests for things like flag format for some challenges which isn't a fault on the support system or player's part, but something we probably should have considered beforehand. For the most part, players were very understanding and respectful which I am quite grateful for.

The scoreboard was interesting to watch, first bloods went a bit slower than I was expecting but that might have been a timezone thing as the solve counts started to make more sense during the second day of the CTF. Players might have also noticed the eligibility scoreboards at the start of the CTF which wasn't really working for the first day. We didn't plan to have it until 2 hours before the CTF started so we quickly put together a script to generate the scoreboard but there were a few infra hiccups with that. Since it wasn't the biggest priority for the time being, it wasn't that stressful, but the infra team managed to fix it up to get a few updates going towards the end of the CTF. It was intense to watch the Swinburne team and the UWA team fight for 2nd place and the UNSW team against the UQ team in the womens category. Blitzkrieg, which consisted of mostly high school students ended up taking the top place in the eligibility bracket winning very comfortably. Pretty impressive, but not exactly surprising if you know who they are.

The duration of the CTF felt a bit long. I am usually not a fan of CTFs that go for longer than 36 hours because it's just very tiring. I didn't get a lot of sleep on the first night because I felt bad for the night shift crew and the tickets just wouldn't stop flowing. That said, I think it's a tradeoff and 48 hours worked well for most people; especially beginners and dedicated competitors who planned to clear their weekend for the CTF. It allowed us to write a lot of challenges spanning a variety of categories and difficulties meaning there would be something for everyone to have fun with.

In the last 2 hours of the CTF there was a debacle with a troll appearing out of nowhere, submitting almost all the flags, reaching 3rd place in a couple minutes, threatening to leak flags, and actually leaking a flag in the Discord. We dealt with them and banned them quickly and kept a close eye on everything for the last 2 hours. They taunted us with messages in the CTFd submissions and caused us quite a lot of stress. They had pretty good opsec and we couldn't exactly figure out who was behind it but after we banned them they seemed to have gone silent and were quickly forgotten about. I was really confused by this; I'm pretty confident it wasn't just one person because there's no way they would have legitimately solved all of those challenges in 46 hours by themselves, and the motive is pretty unclear too. If it was just one person, we'd suspect they pwned us, but if they did they'd have a lot more power than just the flags. If they somehow had access to our private GitHub repo they should've had all the flags but they didn't submit the flag for Substitution Cipher III so we kinda ruled that possibility out as well. We (jokingly) entertained this idea for a bit thinking it was an inside job, it was like a real life game of among us, kinda funny actually. At the end of all of this, I'm still confused and disappointed. It's a shame that people would try to ruin a competition run by volunteers that does nothing but good for the community. If there's something you aren't happy about for whatever reason we are very open to feedback; there's no reason to be so childish and ruin it for everyone else.

# Challenges

I wrote 7 crypto challenges, 7 rev challenges, and 3 pwn challenges. I will briefly comment some thoughts on each challenge I wrote.

|Challenge|Category|Difficulty|
|---|---|---|
|[Substitution Cipher I](#subcipher1)|Crypto|Beginner|
|[Substitution Cipher II](#subcipher2)|Crypto|Easy|
|[treasure](#treasure)|Crypto|Easy|
|[power sign](#power-sign)|Crypto|Hard|
|[yadlp](#yadlp)|Crypto|Hard|
|[1337crypt v2](#1337crypt-v2)|Crypto|Hard|
|[Substitution Cipher III](#subcipher3)|Crypto|Hard|
|[no strings](#no-strings)|Reversing|Beginner|
|[flag loader](#flag-loader)|Reversing|Easy|
|[connect the dots](#connect-the-dots)|Reversing|Medium|
|[flag printer](#flag-printer)|Reversing|Medium|
|[gamer](#gamer)|Reversing|Medium|
|[bullet hell](#bullet-hell)|Reversing|Medium|
|[flag checker](#flag-checker)|Reversing|Hard|
|[babygame](#babygame) (Author: [grub](https://rwx.rip))|pwn|Easy|
|[write what where](#write-what-where)|pwn|Easy|
|[ready, bounce, pwn!](#ready-bounce-pwn)|pwn|Medium|
|[encrypted note](#encrypted-note)|pwn|Hard|

## <a name="subcipher1" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/crypto/substitution-cipher-i">Substitution Cipher I</a>

This was meant to be the beginner crypto challenge. From the feedback, people found it mostly educational and fun but also a bit frustrating. Admittedly, throwing complete beginners a Sage script probably wasn't the best thing to do in hindsight...


## <a name="subcipher2" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/crypto/substitution-cipher-ii">Substitution Cipher II</a>

This was just a sequel to the previous challenge but instead the polynomial is degree 6 and you don't get given it. It got quite a lot of solves but a lot of people struggled understanding that the coefficients of the polynomial are from a finite field. It seemed like a lot of people understood what they needed to do, but lacked the fluency with tools or programming languages to implement a solution. Fortunately, Sage is free and available online to use, so when people asked for help I directed them there and suggested for them to search up ways to solve the system of equations which is well documented on the internet. Most people were able to solve it after this and learnt something new which is good. This challenge was also rated as frustrating in the feedback, probably because of the difficulty to understand the Sage script, in particular the `GF(n)` which probably doesn't mean much to most people...


## <a name="treasure" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/crypto/treasure">treasure</a>

This was a simple challenge based on a made up secret sharing scheme. If you were familiar with modular arithmetic it should have been fairly straightforward. I don't really have much to say about this challenge; there weren't many support requests or complaints about it.


## <a name="power-sign" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/crypto/power-sign">power sign</a>

I wrote this challenge after learning about the Frobenius map and Galois theory. I was expecting it to be on the harder end of hard but I tunnel-visioned too much focusing on the cool math and missed a lot of easy solutions, so it ended up being one of the easier challenges. Regardless, the feedback for this challenge was mostly good.

[Writeup for power sign](https://jsur.in/posts/2021-09-26-ductf-2021-writeups#power-sign)


## <a name="yadlp" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/crypto/yadlp">yadlp</a>

This was the first challenge I submitted for this CTF. It's a kinda standard style of challenge so I was hoping it wouldn't appear in any other CTFs or I would have had to scrap it. I was impressed by the number of solves it had; I was happy to see there were some strong international teams playing. Most solves I saw were intended and the general feedback was positive.

[Writeup for yadlp](https://jsur.in/posts/2021-09-26-ductf-2021-writeups#yadlp)

## <a name="1337crypt-v2" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/crypto/1337crypt-v2">1337crypt v2</a>

This challenge is probably my favourite out of all the crypto challenges. It was the longest standing hard crypto challenge, only being blooded by rkm0959 after I convinced him to check it out despite him being busy with other stuff. It ended up getting three solves which is around what I was expecting. There wasn't a lot of feedback on this challenge because not many people attempted it I guess, but I think people enjoyed it because it was puzzling and unique.

- [Author's Writeup for 1337crypt v2](https://jsur.in/posts/2021-09-26-ductf-2021-writeups#1337crypt-v2)
- [rkm0959's Writeup for 1337crypt v2](https://rkm0959.tistory.com/239)
- [y011d4's Writeup for 1337crypt v2](https://blog.y011d4.com/20210926-ductf-writeup/#1337crypt-v2)


## <a name="subcipher3" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/crypto/substitution-cipher-iii">Substitution Cipher III</a>

I was inspired to write this challenge after the pain I went through trying to understand and solve [runescape](https://blog.cryptohack.org/insane-apocalypse-2021#runescape) from Cyber Apocalypse CTF earlier this year. The challenge itself I think is not too difficult, but working with Sage and getting the implementation working might have been the reason why this challenge only had one solve. It makes sense that the feedback for this was more frustrating than fun since it's kind of a paper challenge and implementation is tedious, but people seemed to have found it educational.

[Writeup for Substitution Cipher III](https://jsur.in/posts/2021-09-26-ductf-2021-writeups#substitution-cipher-iii)


## <a name="no-strings" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/reversing/no-strings">no strings</a>

This was a very easy beginner challenge where you pretty much could have solved it by just looking at the handout binary in a text editor. It had almost a thousand solves and people seemed to find it fun and educational, but also (understandably) boring. I wrote this challenge a long time ago, but noticed only last month a challenge called "nostrings" appeared in CakeCTF which was also a warmup rev challenge. I decided to keep this challenge anyway because I couldn't think of any better name or theme for it, and the challenge concept is slightly different anyway.


## <a name="flag-loader" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/reversing/flag-loader">flag loader</a>

This was an "easy" reversing challenge that probably should have been rated medium. You had to do some trickery and math to solve it which some people got confused about. Understandably, this challenge was frustrating but people also found it educational and fun. I tried to give nudges for this challenge to people who made tickets and most people were able to solve it with only a bit of help. We should probably have had an easier challenge to go between this and no strings.


## <a name="connect-the-dots" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/reversing/connect-the-dots">connect the dots</a>

This was a simple and pretty standard graph traversal problem where you had to figure out how the maze data was packed and find a certain shortest path. I figured since I already had a flag loader, flag printer and flag checker challenge, might as well add some more generic rev challenges. Regardless, people seemed to have enjoyed it which is good.


## <a name="flag-printer" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/reversing/flag-printer">flag printer</a>

This challenge was a Golang binary where you had to figure out what it was doing and then optimise it. It had quite a bit of math elements in it because the operations being performed were matrix multiplications and exponentiations with massive numbers. There weren't any ticket requests for this challenge at all and the feedback is pretty consistent between frustrating, educational, and fun.


## <a name="gamer" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/reversing/gamer">gamer</a>

This challenge was a pain to make, so I'm relieved it was received relatively well. The inspiration for this challenge came from trying to see how easy it would be to hack other similar games online (for research purposes only!). I hadn't worked with Unity before so it was something new to learn. Reversing the actual game wasm probably would have been too difficult/tedious and I think almost all teams solved the intended way which was to hook the Unity game objects. Admittedly, this challenge was not really reversing and that might have been a little bit misleading for people.


## <a name="bullet-hell" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/reversing/bullet-hell">bullet hell</a>

This was probably my favourite reversing challenge. You had to play a bullet hell game and beat it to get the flag, but the bullets were hidden so you had to reverse the given binary to figure out how they were generated. There were some really neat solutions to this that solved the game dynamically, one [here](https://gist.github.com/uint0/f357856d4f386dd5233daa7408b0f01a) by another challenge author and one by [justinsteven](https://twitter.com/justinsteven) who told me about his solution in DMs. There was also apparently a solution where you could get the flag by messing with the terminal window size 🤔. Overall, people found this challenge fun and so did I!


## <a name="flag-checker" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/reversing/flag-checker">flag checker</a>

I don't really have much to say about this challenge. It was meant to be a math/crypto inspired chall but z3 seems to solve it pretty easily (I should have known this, in hindsight). The hard difficulty tag is probably a bit misleading as it seems flag printer and bullet hell were harder.


## <a name="babygame" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/pwn/babygame">babygame</a>

This challenge was contributed by an external author but I was in charge of responding to support requests for it. People generally enjoyed this challenge and it was accessible to even beginners, while still being fun to solve for more advanced players. There were some issues with the challenge because it required knowing a file that existed on the server and some players made incorrect assumptions about the remote environment. This was a fault on my part, but the challenge would still be solvable without any guessing. It made me think that it might be good to provide Dockerfiles or provide players with an easy way of testing against the exact environment running on the server.


## <a name="write-what-where" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/pwn/write-what-where">write what where</a>

This was an easy pwn challenge which gave you one 4 byte arbitrary write. Most players figured out an easy first step to turn this into an infinite number of writes, but got a bit stuck after that. When writing the challenge, I missed that there was an easy solution that succeeds with 1/4096 reliability. It seemed like a lot of players noticed this but I tried to discourage it (since it counts as bruteforcing, kinda, and there are other solutions which are nicer). Overall, people found the challenge educational.


## <a name="ready-bounce-pwn" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/pwn/ready-bounce-pwn">ready, bounce, pwn!</a>

This was a medium challenge that lets you modify `rbp`. People seemed to generally understand how this could be exploited, but some struggled with figuring out how to get around the restrictions involved. I was a bit surprised that the challenge didn't get more solves as I initially thought it was about the same or easier in difficulty compared to write what where. Like most other challenges, this challenge seemed to have had an even distribution of frustration, educational and fun factors.


## <a name="encrypted-note" href="https://github.com/DownUnderCTF/Challenges_2021_Public/tree/main/pwn/encrypted-note">encrypted note</a>

This was the first pwn challenge I had written. It involves crypto concepts as well, but the pwn part and crypto part independently are not very difficult themselves. The most difficulty from this challenge comes from working out how to abuse both parts simultaneously. Admittedly, it is also a pretty tedious challenge in the sense that to solve it you probably need to debug a lot. It seems like some people also had issues with exploits working locally but not on remote which might have been frustrating. There was some negative feedback about mixing the two categories which makes sense from the perspective of someone who only does pwn and isn't interested much in crypto.

# Survey Feedback

The feedback we received was overwhelmingly positive while also having good points of constructive feedback for all of us. I am grateful to everyone who submitted their honest thoughts! The main points were things like providing source for challenges, making the flag formats easier to understand, better variety for rev/pwn challs, etc. which I completely agree with. The team will get to reading all the feedback and discussing it together at some point, but for now we are gonna take a bit of a rest and time away from the screen.
