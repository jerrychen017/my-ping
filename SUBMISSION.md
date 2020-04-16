# Cloudflare Internship Application: Systems

Hey recruiters,
I hope you are doing well in this pandemic. 
Here's my ping program.  

## How to run
- You need to have root access and `sudo` since I'm using SOCK_RAW. 
- You also need to have `en0` interface if you want to run `-IPV6`. 
- Makefile is included. 

## Features
- `-IPV6`: ping using IPv6
- `-verbose`: print out the content of each ICMP packet.
- `-c <count>`: send `<count>` number of packets
- `-TTL <number between 0 and 255>`: setup ttl
