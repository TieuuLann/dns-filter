# dns-filter
This is a very basic tiny DNS server with ability to filter requests. Suitable for simple ad blocking, minimalistic Pi-hole analog. 

Current source code components:
* Mongoose (https://github.com/cesanta/mongoose)
* uthash (https://github.com/troydhanson/uthash)

## Technical specs:
* only UDP protocol
* only one thread
* only one async socket
* no caching
* unlimited number of upstream DNS servers (see file **dns.txt**)
* unlimited number of filtered domains (see file **hosts.txt**)
* capable to process up to 64k DNS requests simultaneously
* written in pure С (cross-platform, tested on windows and linux)
* everything except above is not supported (TCP handling, DoH, DoT etc)

## Compilation on Windows:
1. Open **dns-filter.sln** with visual studio and build it
2. Run **dns-filter.exe** to start it
3. Be happy

## Compilation on Linux:
1. Run **gcc -w src/\*.c -o dns-filtergcc -w src/*.c -o dns-filter** within project folder
2. Run **sudo ./dns-filter** to start it
3. Be happy
