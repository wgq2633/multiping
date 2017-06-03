class IPTracking:
    def __init__(self, ip, seq, ts):
        self.timestamp = ts
        self.ip = ip
        self.seq = seq
        self.timeout = False
        self.ping = 0.0
        self.error_code = 0
        self.error_msg = ""

    def set_delay(self, delay):
        self.ping = delay

    def set_error(self, error_code, error_msg):
        self.error_code = error_code
        self.error_msg = error_msg

    def set_timeout(self):
        self.timeout = True


class SummaryData:
    def __init__(self, hostname):
        self.hostname = hostname
        self.curr_delay = 0.0
        self.total_delay = 0.0
        self.amount_updates = 0
        self.total_errors = 0
        self.total_timeouts = 0
        self.highest_delay = 0
        self.ok_counter = 0

    def update(self, iptracking):
        if isinstance(iptracking, IPTracking):

            if iptracking.error_code > 0:
                self.total_errors += 1
            elif iptracking.timeout:
                self.total_timeouts += 1
            else:
                self.ok_counter += 1
                self.curr_delay = iptracking.ping
                self.total_delay += iptracking.ping
                self.amount_updates += 1
                if self.highest_delay < self.curr_delay:
                    self.highest_delay = self.curr_delay

    def calc_avg_delay(self):
        if self.amount_updates > 0:
            return round(self.total_delay / self.amount_updates, 4)
        else:
            return 0.0


class ControlCommand:
    def __init__(self, cmd_val):
        self.command = cmd_val

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
