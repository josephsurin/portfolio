---
path: /post/2020-02-19-tshark-cheatsheet
title: tshark Cheatsheet
date: 2020-02-19
tags: ctf,infosec,random
---

## BASICS

Read from a pcap: `tshark -r <file.pcap>`

Print TCP conversations: `tshark -r <file.pcap> -z conv,tcp` (add `-q` to suppress packet info)

Print field-formatted: `tshark -r <file.pcap> -T fields -e <field1> -e <field2> ...`

List User-Agents: `tshark -r <file.pcap> -T fields -e http.user_agent`

Print X.509 certs: `tshark -r <file.pcap> -T fields -R "ssl.handshake.certificate" -e x509sat.printableString`

Apply a display filter: `tshark -r <file.pcap> -Y <display filter>`

Print packet summaries for TCP packets to port 71: `tshark -r <file.pcap> -Y "tcp.dstport == 71"`

Display contents of TCP stream between 10.0.0.1 port 123 and 10.0.0.2 port 456: `tshark -r <file.pcap> -z "follow,tcp,ascii,10.0.0.1:123,10.0.0.2:456"`

Decrypt WPA traffic (`-o <pref>:<val>` overrides preference) and print http file data: `tshark -r <file.pcap> -o wlan.enable_decryption:TRUE -o "uat:80211_keys:\"wpa-pwd\",\"password:<w1F1-P4ssw0rD\"" -T fields -e http.file_data`

Decrypt using SSL keys: `tshark -r <file.pcap> -o 'uat:rsa_keys:"./server_private_key.pem",""' -Tfields -e text `

Decrypt with pre master secret: `tshark -r <file.pcap> -o 'tls.keylog_file:./premastersecret.txt' -T fields -e http.request.uri`

Show detailed view of http packets and summaries of others: `tshark -r <file.pcap> -O http`

List possible fields: `tshark -G`

## Fields Cheatsheet

The field `text` on its own may sometimes work (e.g. for HTTP and FTP)

#### Ethernet `eth`

https://www.wireshark.org/docs/dfref/e/eth.html

`addr`, `len`, `src`, `dst`, `lg`, `trailer`, `ig`, `multicast`, `type`

#### IPv4 `ip`

https://www.wireshark.org/docs/dfref/i/ip.html

`addr`, `checksum`, `checksum_bad`, `checksum_good`, `dst`, `dst_host`, `flags`, `flags.df`, `flags.mf`, `flags.rb`, `hdr_len`, `host`, `id`, `len`, `proto`, `reassembled_in`, `src`, `src_host`, `tos`, `tos.cost`, `tos.delay`, `tos.precedence`, `tos.reliability`, `tos.throughput`, `ttl`, `version`

#### IPv6 `ipv6`

https://www.wireshark.org/docs/dfref/i/ipv6.html

`addr`, `dst`, `dst_host`, `hlim`, `host`, `nxt`, `opt.pad1`, `opt.padn`, `plen`, `reassembled_in`, `src`, `src_host`, `version`

#### TCP `tcp`

https://www.wireshark.org/docs/dfref/t/tcp.html

`ack`, `checksum`, `checksum_bad`, `checksum_good`, `continuation_to`, `dstport`, `flags`, `flags.{ack,cwr,ecn,fin,push,reset,syn,urg}`, `hdr_len`, `len`, `nxtseq`, `options`, `options.{cc,ccecho,ccnew,echo,echo_reply,md5,mss,mss_val,qs,sack,sack_le.sack_perm,sack_re,time_stamp,wscale,wscale_val}`, `pdu.{last_frame,size,time}`, `port`, `reassembled_in`, `segment`, `segment.{error,multipletails,overlap,overlap.conflict,toolongfragment}`, `segments`, `seq`, `srcport`, `time_delta`, `time_relative`, `urgent_pointer`, `window_size`, `payload`

#### UDP `udp`

https://www.wireshark.org/docs/dfref/u/udp.html

`checksum`, `checksum_bad`, `checksum_good`, `dstport`, `length`, `port`, `srcport`

#### HTTP `http`

https://www.wireshark.org/docs/dfref/h/http.html

`accept`, `accept_encoding`, `accept_language`, `authbasic`, `authorization`, `cache_control`, `connection`, `content_encoding`, `content_length`, `content_type`, `cookie`, `date`, `file_data`, `host`, `last_modified`, `location`, `notification`, `proxy_authenticate`, `proxy_authorization`, `proxy_connect_host`, `proxy_connect_port`, `referer`, `request`, `request.{full_uri,method,uri,version}`, `request.uri.{path,query,query.parameter}`, `response`, `response.{code,code.desc,phrase}`, `server`, `set_cookie`, `transfer_encoding`, `user_agent`, `www_authenticate`, `x_forwarded_for`

#### SSL `ssl`

https://www.wireshark.org/docs/dfref/s/ssl.html

`handshake`, `handshake.{cert_status,cert_status_len,cert_status_type,cert_type,cert_types,cert_types_count,certificate,certificate_length,challenge,challenge_length,cipher_spec_len,cipher_suites_length,cipherspec,ciphersuiteciphersuites,clear_key_data,clear_key_lengthclient_cert_vrfy.sig,client_cert_crfy.sig_len,client_point,client_point_len,comp_method,comp_methods,comp_methods_length,connection_id,connection_id_length,encrypted_key,encrypted_key_length,epms,epms_len,exponent,exponent_len,extension.data,extension.len,modulus,modulus_len,identity,identity_len,server_point,server_point_len}`, `handshake.cert_type.{type,types,types_len}`

#### FTP `ftp`

(not prefixed): `ftp-data.command`, `ftp-data.setup-method`, `ftp-data.current-working-directory`

`active.{cip,nat,port}`, `command`
