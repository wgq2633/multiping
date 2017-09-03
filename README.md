# multiping
Multiping is a small application which works very similar to PING, but the main difference that it allows to send the IMCP packets to multiple servers at once.

**Example of usage**
```sh
$ python ping.py [options] <ip-address|hostname> <ip-address-range> ...
    ip-address|hostname:
            any ip address or hostname
    ip-address-range:
            ip address ranges can be: 192.168.{1-5}.7 or '192.168.{1-2-5}.7'
            you'd better quote your ip-address-range arguments with apostrophe sign('), to avoid it to be expanded by SHELL.
            '192.168.{1-5}.7' : the 3rd part is in interger set [1,5], i.e.{ 192.168.1.7 192.168.2.7 192.168.3.7 .... 192.168.5.7 }
            '192.168.1.{1-2-5}':the 4th part is in interger set [1,5] but with stepper of 2, i.e. { 192.168.1.1 192.168.1.3 192.168.1.5}
    options:
            -L,--less-info  don't show AVG&MAX DELAY value.
```

**Example output**
```
               09-03 20:06:38
 Current time:09-03 20:06:44     Running from: 09-03 20:06:23    Running time: 00:00:21
HOST            =====      [DELAY/ms                CUR         AVG         MAX] ERRORS TIMEOUTS/%
lo              =======>   [.....                0.3488      0.4531      0.9899]      0      0/0.00
192.168.168.168 >          [                     0.0000      0.0000      0.0000]      0      1/100.00
192.168.0.1     =======>   [.............        1.6241      1.4154      1.7920]      0      0/0.00
as2             =====>     [..............     127.0440    127.3017    127.5311]      0      0/0.00
m.baidu.com     ======>    [..............      23.3269     23.4005     24.1599]      0      0/0.00
github.com      >          [                   245.4059      0.0000      0.0000]      0      1/100.00
```