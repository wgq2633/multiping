import random
import sys
import socket
import struct
import select
import time
import signal
import threading
from time import sleep, strftime

default_timer = time.time

ICMP_ECHO_REQUEST = 8

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
            msg = ("[%s] ICMP REQUEST TO %s\t icmp_seq=%d\t" % (strftime("%m.%d %H:%M:%S"), self.dest_addr, self.seq))
            try:
                delay = self.do_one()
                if delay is None:
                    msg += ("failed. (timeout within %ssec.)" % self.timeout)
                elif delay > 0:
                    delay *= 1000
                    msg += ("time=%0.4f ms" % delay)
                else:
                    msg += "(socket error: No route to host)"
            except socket.error as e:
                msg += ("failed. (socket error: '%s')" % e[1])

            self.msg_queue.push(msg)
            self.seq = (self.seq+1) & 0xFFFF
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


class MessageQueue:
    def __init__(self):
        self.queue = []

    def push(self, message):
        self.queue.append(message)

    def pop(self):
        ret = None
        if self.len > 0:
            ret = self.queue.pop(0)
        return ret

    @property
    def len(self):
        return len(self.queue)


class Printing(threading.Thread):
    def __init__(self, msg_queue):
        threading.Thread.__init__(self)
        self.msg_queue = msg_queue

    def run(self):
        global run_loop
        loop = True
        while loop:
            sleep(1)
            while self.msg_queue.len>0:
                item = self.msg_queue.pop()
                if item is not None:
                    print item
            if self.msg_queue.len == 0 and not run_loop:
                loop = False


def exit_method(signal, frame):
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


if __name__ == "__main__":

    signal.signal(signal.SIGTERM, exit_method)
    signal.signal(signal.SIGINT, exit_method)

    msg_queue = MessageQueue()

    threads = []

    randomSeqNr = random.sample(range(1, 0x7FFF), sys.argv[1:].__len__())

    for ip in sys.argv[1:]:
        if is_valid_ipv4_address(ip):
            threads.append(Runner(ip, msg_queue, randomSeqNr.pop()))

    threads.append(Printing(msg_queue))

    for thread in threads:
        thread.start()

    while True:
        if not any([thread.isAlive() for thread in threads]):
            break
        else:
            for thread in threads:
                thread.join(1)
