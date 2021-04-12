# dns-filter
This is a very basic tiny DNS server with ability to filter requests. Suitable for simple ad blocking, minimalistic Pi-hole analog. 

Current source code components:
* Mongoose (https://github.com/cesanta/mongoose)
* uthash (https://github.com/troydhanson/uthash)

Technical specs:
* only UDP protocol
* only one thread
* only one async socket
* no caching
* unlimited number of upstream DNS servers (see file **dns.txt**)
* unlimited number of filtered domains (see file **hosts.txt**)
* capable to process up to 64k DNS requests simultaneously
* written in pure С (need minor changes to compile for non-windows platforms)
* everything except above is not supported (TCP handling, DoH, DoT etc)
