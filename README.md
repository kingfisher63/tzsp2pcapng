# tzsp2pcapng

*Tzsp2pcapng* converts a stream of [TaZmen Sniffer Protocol](http://en.wikipedia.org/wiki/TZSP)
(TZSP) packets to PcapNG formatted data on stdout.

# Usage

```
$ tzsp2pcapng -h

tzsp2pcapng v1.0.0 - TZSP (TaZmen Sniffer Protocol) to PcapNG converter

Options:
  -C file_size         Rotate output file after file_size bytes (range 1024-4294967295)
  -f                   Flush output after every packet
  -F ip_address        Accept only TZSP messages from ip_address
  -G file_age          Rotate output file after file_age seconds (range 60-604800)
  -h                   Print this message and exit
  -H hardware          Capture hardware (PcapNG only)
  -I interface         Capture interface (PcapNG only)
  -O operating_system  Capture operating system (PcapNG only)
  -p port              UDP port to listen on (default: 37008)
  -P                   Write legacy Pcap format
  -v                   Print verbose information on stderr
  -w file              Write data to a file ('-' = stdout)
  -z command           Run command after output file rotation
```

Run `man tzsp2pcapng` after installation for detailed usage information.

# Building and packaging

The basic workflow to build and package *tzsp2pcapng* is
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ cpack
```

On platforms that have *dpkg* (Debian Linux and its derivatives) cpack creates a
Debian package (.deb) by default. On other platforms cpack creates a gzipped tar
archive (.tar.gz).

# Author

Roger Hunen
