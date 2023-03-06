class Connection:
    CLOSED = 0
    AVAILABLE = 1
    HALF_CLOSED = 2

    def __init__(self):
        self.sid = None
        self.buffer = ""
        self.status = self.CLOSED

    def append_msg(self, msg):
        self.buffer += msg
