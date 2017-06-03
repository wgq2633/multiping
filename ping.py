#!/usr/bin/python

import random
import sys
import socket
import struct
import select
import time
import signal
import threading
from time import sleep, strftime
import os
from structs import IPTracking, SummaryData, ControlCommand, MessageQueue
import re

default_timer = time.time

last_ctrl_c_time_sec = 0

ICMP_ECHO_REQUEST = 8


CTRL_CMD_NONE = 0
CTRL_CMD_CLEAR_OK_COUNTER = 1

run_loop = True


class Runner(threading.Thread):
    def __init__(self, dest_addr, msg_queue, startId):
        threading.Thread.__init__(self)
        self.dest_addr = dest_addr
        self.timeout = 4
        self.seq = startId & 0xFFFF
        self.msg_queue = msg_queue

    def run(self):
        global run_loop
        while run_loop:
            data = IPTracking(self.dest_addr, self.seq, default_timer())
            try:
                delay = self.do_one()
                if delay is None:
                    data.set_timeout()
                elif delay > 0:
                    delay *= 1000
                    data.set_delay(delay)
            except socket.error as e:
                data.set_error(e[0], e[1])

            self.msg_queue.push(data)
            self.seq = (self.seq + 1) & 0xFFFF
            sleep(1)

    def receive_one_ping(self, my_socket, seq_id):
        """
        receive the ping from the socket.
        """
        time_left = self.timeout
        while True:
            started_select = default_timer()
            what_ready = select.select([my_socket], [], [], time_left)
            how_long_in_select = (default_timer() - started_select)
            if not what_ready[0]:  # Timeout
                return

            time_received = default_timer()
            rec_packet, addr = my_socket.recvfrom(1024)
            icmp_header = rec_packet[20:28]
            type, code, checksum, packet_seq_id, sequence = struct.unpack(
                "bbHHh", icmp_header
            )

            if type != 8 and packet_seq_id == seq_id:
                bytes_in_double = struct.calcsize("d")
                time_sent = struct.unpack("d", rec_packet[28:28 + bytes_in_double])[0]
                return time_received - time_sent

            time_left -= how_long_in_select
            if time_left <= 0:
                return

    def send_one_ping(self, my_socket, dest_addr, ID):
        """
        Send one ping to the given >dest_addr<.
        """
        dest_addr = socket.gethostbyname(dest_addr)

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        my_checksum = 0

        # Make a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_in_double = struct.calcsize("d")
        data = (192 - bytes_in_double) * "Q"
        data = struct.pack("d", default_timer()) + data

        # Calculate the checksum on the data and the dummy header.
        my_checksum = self.checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
        )
        packet = header + data

        my_socket.sendto(packet, (dest_addr, 1))  # Don't know about the 1

    def do_one(self):
        """
        Returns either the delay (in seconds) or none on timeout.
        """
        icmp = socket.getprotobyname("icmp")
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error, (errno, msg):
            if errno == 1:
                # Operation not permitted
                msg += " - Note that ICMP messages can only be sent from processes"
                raise socket.error(msg)
            raise  # raise the original error

        my_id = self.seq & 0xFFFF

        self.send_one_ping(my_socket, self.dest_addr, my_id)
        delay = self.receive_one_ping(my_socket, my_id)

        my_socket.close()
        return delay

    def checksum(self, source_string):

        sum = 0
        count_to = (len(source_string) / 2) * 2
        count = 0
        while count < count_to:
            sum += ord(source_string[count + 1]) * 256 + ord(source_string[count])
            sum &= 0xffffffff
            count += 2

        if count_to < len(source_string):
            sum += ord(source_string[len(source_string) - 1])
            sum &= 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)
        sum += sum >> 16
        answer = ~sum
        answer &= 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        return answer


def p_helper(value, length=9):
    l = "%.4f" % value
    return " " * (length - len(l)) + l


def p_helper1(curr, max, avg, size=20):
    if max < 0.1:
        point = 0
    else:
        point = int(curr / max * size)
    if point > size:
        point = size

    return u"[%s%s| %s ms AVG: %s ms MAX: %s ms]" % (
        '.' * point, ' ' * (size - point), p_helper(curr), p_helper(avg), p_helper(max))


class Printing(threading.Thread):
    def __init__(self, msg_queue, valid_ips):
        threading.Thread.__init__(self)
        self.msg_queue = msg_queue
        self.data = {}
        self.valid_ips = valid_ips
        self.start_from = default_timer()
        for ip in valid_ips:
            hostname=( ip2hostname_map[ip] if (ip in ip2hostname_map)  else ip )
            self.data[ip] = SummaryData(hostname)

    def run(self):
        global run_loop
        loop = True
        
        print("\033[2J")
        while loop:
            stdout_linenum=2
            sleep(1)
            while self.msg_queue.len > 0:
                item = self.msg_queue.pop()
                if item is not None and isinstance(item, IPTracking):
                    self.data[item.ip].update(item)
                elif item is not None and isinstance(item, ControlCommand):
                    for ip,info in self.data.iteritems():
                        info.ok_counter = info.total_errors = info.total_timeouts = 0
                        info.highest_delay = info.total_delay = 0
                        info.amount_updates = 0
                del item

            delta = default_timer() - self.start_from
            d_hours = int(delta / 3600)
            delta -= d_hours * 3600
            d_mins = int(delta / 60)
            delta -= d_mins * 60

            print "\033[%d;0H\033[K" % stdout_linenum,
            stdout_linenum+=1
            print "Current time: %s\t\tRunning from: %s\t\tRunning time: %02d:%02d:%02d" % (
                strftime("%m-%d %H:%M:%S"), strftime("%m-%d %H:%M:%S", time.localtime(self.start_from)),
                d_hours, d_mins, delta
            )
            
            ipid=0
            for ip in self.valid_ips:
                info = self.data[ip]
                style=("\033[33m" if ipid%2==0 else "\033[35m")
                ipid=ipid+1
                print "%s\033[%d;0H\033[K" % (style,stdout_linenum),
                stdout_linenum+=1
                
                timeout_rate=100.0
                if info.amount_updates>0:
                    timeout_rate=100.0*info.total_timeouts/info.amount_updates
                print "%-25s %-10s DELAY:%s\tERRORS: %d\tTIMEOUTS: %d/%-3.2f%%]\033[0m" % \
                      (info.hostname, 
                      ("=" * (info.ok_counter%10) + ">" ),
                      p_helper1(info.curr_delay, info.highest_delay, info.calc_avg_delay()), info.total_errors,
                       info.total_timeouts, timeout_rate)

            if self.msg_queue.len == 0 and not run_loop:
                loop = False


def exit_method(signal, frame):
    global last_ctrl_c_time_sec
    cur_time_sec = time.time()
    print "\033[2J\033[0;15H\033[K %s" % strftime("%m-%d %H:%M:%S")
    last_ctrl_c_time_sec_bak = last_ctrl_c_time_sec
    last_ctrl_c_time_sec = cur_time_sec
    if cur_time_sec - last_ctrl_c_time_sec_bak > 1:
        msg_queue.push( ControlCommand(CTRL_CMD_CLEAR_OK_COUNTER) )
        return

    global run_loop
    run_loop = False
    print("STOPPING")


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

# parsing num pattern
def parse_num_segements(numsegment_rex_match):
    ipsegs=numsegment_rex_match.group(1).split(",")
    num_segs=[]
    for ipseg in ipsegs:
        ipseglst=ipseg.split("-")
        ipsegstart=ipseglst[0]
        ipseglast=ipseglst[-1]
        
        rex_digit=re.compile("^-?\d+$")
        rex_match=rex_digit.search(ipsegstart)
        if rex_match is None:
            print("invalid ip segement start %s" % ipseg)
            continue;
        ipsegstart=int(ipsegstart);
        
        rex_match=rex_digit.search(ipseglast)
        if rex_match is not None:
            ipseglast=int(ipseglast);
        else:
            ipseglast=-1
        
        ipsegstep=0
        if len(ipseglst)>=3:
            ipsegstep=ipseglst[1]
            rex_match=rex_digit.search(ipsegstep)
            if rex_match is not None:
                ipsegstep=int(ipsegstep);
        if ipsegstart<1 or ipsegstart>254: ipsegstart=1
        if ipsegstep==0:
            if ipseglast<ipsegstart: ipsegstep=-1
            else: ipsegstep=1
        if ipseglast<1 or ipseglast>254:
            if ipsegstep>0: ipseglast=254
            else: ipseglast=1
           
        print("[%d,%d]%d" %(ipsegstart, ipseglast, ipsegstep) )
        num_segs.extend( range(ipsegstart, ipseglast+ipsegstep, ipsegstep) )
        
    return (None if len(num_segs)<1 else num_segs)
    

if __name__ == "__main__":
    global msg_queue
    
    signal.signal(signal.SIGTERM, exit_method)
    signal.signal(signal.SIGINT, exit_method)

    msg_queue = MessageQueue()

    threads = []
    valid_ips = []
    ip2hostname_map = {}
    

    for ip in sys.argv[1:]:
        if is_valid_ipv4_address(ip):
            threads.append(Runner(ip, msg_queue, random.randint(1,0x7FFF) ))
            valid_ips.append(ip)
            print "ipistr=%s" % ip
        else:
            ipsegment_rex_match=re.compile("\{([,\-0-9]+)\}").search(ip)
            if ipsegment_rex_match is None:
                hostname=ip;
                ipistr=socket.gethostbyname(hostname)
                print("host:%s => %s" %(hostname, ipistr) )
                ip2hostname_map[ipistr] = hostname
                threads.append(Runner(ipistr, msg_queue, random.randint(1,0x7FFF)))
                valid_ips.append(ipistr)
            else:
                ipprefix=ip[0:ipsegment_rex_match.start()]
                ipsuffix=""
                endpos=ipsegment_rex_match.end()
                if endpos< len(ip): ipsuffix=ip[endpos:]
                
                ipseglst=parse_num_segements(ipsegment_rex_match)
                for ipi in ipseglst:
                    ipistr=("%s%d%s" %(ipprefix, ipi, ipsuffix) )
                    #print "ipistr=%s" % ipistr
                    if is_valid_ipv4_address(ipistr): 
                        print "ipistr=%s" % ipistr
                        threads.append(Runner(ipistr, msg_queue, random.randint(1,0x7FFF)))
                        valid_ips.append(ipistr)
    #exit(1)
    threads.append(Printing(msg_queue, valid_ips))

    for thread in threads:
        thread.start()

    while True:
        if not any([thread.isAlive() for thread in threads]):
            break
        else:
            for thread in threads:
                thread.join(1)
