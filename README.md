# merg
A tool for merging pcap files by firstly loading it in memory. Typical wireshark merge was very very slow by reading pcap files in a non-sequential way.

#TODO
The memory allocation is not treated well and one can run out of memory in case of merging really big files.

#NOTE
It's not obsolete and useless as it's an old project. It's not usable on SSD at all.
