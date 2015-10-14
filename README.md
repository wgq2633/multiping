# multiping
Multiping is a small application which works very similar to PING, but the main difference that it allows to send the IMCP packets to multiple servers at once.

**Example of usage**
```sh
$ python ping.py <ip-address> <ip-address> ...
```

**Example output**
```
Current time: 10-14 08:50:00		Running from: 10-14 08:00:00		Running time: 00:50:00
[192.168.1.1]	DELAY:[#####...............|    1.8299 ms AVG:    3.2295 ms MAX:   77.9240 ms]	ERRORS: 0	TIMEOUTS: 191]
[8.8.8.8]	DELAY:[##..................|    6.6450 ms AVG:   20.7637 ms MAX:  251.2622 ms]	ERRORS: 0	TIMEOUTS: 28]
[192.168.5.5]	DELAY:[#########...........|    1.6210 ms AVG:    2.2818 ms MAX:  105.5570 ms]	ERRORS: 0	TIMEOUTS: 0]
[192.168.5.25]	DELAY:[....................|    1.6658 ms AVG:    2.1498 ms MAX:   80.8280 ms]	ERRORS: 0	TIMEOUTS: 0]
```