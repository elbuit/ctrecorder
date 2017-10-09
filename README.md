# About

ctrecorder uses nf_conntrack_netlink module to receive netfilter events, that is adding and destroying conntrack entries.
This allows saving start and end time of connection for specific protocol. Currently TCP and UDP are supported.
Main application of ctrecorder is connections logging for security and anti-abuse reasons.

Logs are especially useful for NAT-ed connection, as they contain both pre-NAT and post-NAT IPs and ports.
Be aware, that using NOTRACK in raw table will hide packets from conntrack and effectively from ctrecorder too.

TODO

# Manuals.


# Bugs

Description	Version	Status*	Temporary fix
log records may (will) be broken (out of sync) after log write error occurs (ex. out of space)	<=0.1.3	pending	keep enough free space on the drive
ctrecorder dies ocasionally during log reading in squeeze mode	*	pending	try non-squeeze mode
Any version does not guarantee compatibility with older/newer files	*	-	Keep copy of each version installation tarball to read log files


# Downloads

Sources released under GNU License.
If you use this software, please send me an e-mail with comment. Thank you.

Latest version:
ctrecorder-0.1.6.tar.gz

# Security

ctrecorder daemon does not use user supplied payload (except command line), therefore should be fairly secure to run even as root. Current version may or may not run as non-root (work in progress).
Remember that logs (and log directory itself) should have apropriate permissions, preventing unauthorized access.
ctrecorder refuses to overwrite log files. If this is the case during log file change, daemon continues to write to old file. It should not be made setuid-root though.


# Example

record conntrack events for TCP, creating new file every 360 minutes (at 0:00, 6:00, 12:00, 18:00 GMT); exact time depend on system timezone
```# mkdir -m 0700 /var/log/ct/
# ctrecorder -Cf /var/log/ct/tcp-%Y%m%d-%H%M%S.ct -t 360
```
record conntrack events for UDP, creating new file every 180 minutes (at 0:00, 3:00, 6:00 GMT, and so on), using non-default buffer sizes
```# mkdir -m 0700 /var/log/ct/
# ctrecorder -Cf /var/log/ct/udp-%Y%m%d-%H%M%S.ct -p udp -t 180 -b 2048 -B 3000
```
find connection from/to 192.168.1.100; here: connection from 88.1.1.1 to 194.1.1.1 (DNAT-ed to 192.168.1.100)
```$ ctrecorder -Lf /var/log/ct/tcp-20100101-010101.ct -i 192.168.1.100
2010.09.28 21:15:17.988012 S  src=88.1.1.1:1527 dst=194.1.1.1:25 src=192.168.1.100:25 dst=88.1.1.1:1527
2010.09.28 21:15:17.989960 E  src=88.1.1.1:1527 dst=194.1.1.1:25 src=192.168.1.100:25 dst=88.1.1.1:1527
find connection from/to 192.168.1.100:80, show using squeezed (double-column or one-line) format
$ ctrecorder -Lf /var/log/ct/tcp-20100101-010101.ct -i 192.168.1.100 -p 80 -s
2010.09.28 21:15:17.988012 2010.09.28 21:15:17.989960 src=88.1.1.1:1527 dst=194.1.1.1:80 src=192.168.1.100:80 dst=88.1.1.1:1527
```

# FAQ

You can get simple command-line help:
```$ ctrecorder -h
Usage: ctrecorder [ -C | -L | -T | -S | -H | -h | -V ] options ...
capture mode: ctrecorder -C ... (disabled at compilation time)
  -f path          output filename, conforming to strftime format, ex. /tmp/ct-%Y%m%d-%H%M%S.log
  -t minutes       output name change interval
  -p name          record for protocol: tcp, udp (default: TCP)
  -b kbytes        netlink buffer size
  -B entries       internal buffer size
  -N nice          priority
  -U name          run as user
  -G name          run as group
  -P path          pid file
  -F               run foreground
list mode: ctrecorder -L -f path [ -i IP/MASK ] [ -p PORT ]
  -f path          input filename
  -i IP/mask       list only matching this network
  -p port          list only matching this port
  -s               squeeze output
  -H               hide header
show header only: ctrecorder -H -f path
  no optional arguments
test mode: ctrecorder -T -f path
  -f path          input filename
squeeze mode: ctrecorder -S -f path [ -o path ]
  -f path          input filename
  -o path          output filename
```
You need to have conntrack events enabled in your kernel config (most of the recent distributions do); otherwise daemon will not log any connections, and it will not log any error or warning:
 $ grep CONFIG_NF_CONNTRACK_EVENTS /boot/config-`uname -r`
CONFIG_NF_CONNTRACK_EVENTS=y

You can also verify connection tracking events usability by running conntrack (usually found in conntrack package):
 $ conntrack -E
 [UPDATE] udp      17 29 src=94.1.1.1 dst=212.2.2.2 sport=41301 dport=53 src=212.2.2.2 dst=94.1.1.1 sport=53 dport=41301
 [UPDATE] udp      17 180 src=94.1.1.1 dst=212.2.2.2 sport=41301 dport=53 src=212.2.2.2 dst=94.1.1.1 sport=53 dport=41301 [ASSURED]
    [NEW] tcp      6 120 SYN_SENT src=94.1.1.1 dst=85.3.3.3 sport=39790 dport=80 [UNREPLIED] src=85.3.3.3 dst=94.1.1.1 sport=80 dport=39790
^C

You may compile ctrecorder on non-Linux machine just to read the logs (without capture code):
```$ ./configure --disable-capture
[...]
configure: -----------------------------------------------------------
configure: setup: enable capture: no
configure: -----------------------------------------------------------
[...]
$ make
[...]
$ ./src/ctrecorder -V
ctrecorder 0.1.3, compiled Sep 28 2010 22:51:09
log format 0x00000002
struct file_header size: 256
struct common size: 33
struct combined size: 40
Capture mode support disabled at compilation time!
```
# Manuals

Todo.


(c) 2005-2013 Bartłomiej Korupczyński
