import binascii
import struct
from threading import Lock
from mitmproxy import ctx


class RC4:
    def __init__(self):
        self.state = [None] * 256
        self.p = self.q = None

    def setKey(self, key):
        # RC4 Key Scheduling Algorithm
        self.state = [n for n in range(256)]
        self.p = self.q = j = 0
        for i in range(256):
            if len(key) > 0:
                j = (j + self.state[i] + key[i % len(key)]) % 256
            else:
                j = (j + self.state[i]) % 256
            self.state[i], self.state[j] = self.state[j], self.state[i]

    def byteGenerator(self):
        # RC4 Pseudo-Random Generation Algorithm
        self.p = (self.p + 1) % 256
        self.q = (self.q + self.state[self.p]) % 256
        self.state[self.p], self.state[self.q] = self.state[self.q], self.state[self.p]
        return self.state[(self.state[self.p] + self.state[self.q]) % 256]

    def encrypt(self, inputBytes):
        # Encrypt input string returning a byte list
        return [p ^ self.byteGenerator() for p in inputBytes]

    def decrypt(self, inputByteList):
        # Decrypt input byte list returning a string
        return bytes([c ^ self.byteGenerator() for c in inputByteList])


class OracleForms:
    def __init__(self):
        self.gday = None
        self.mate = None
        self.key = [None] * 5
        self.rc4_req = None
        self.rc4_resp = None
        self.req_lock = Lock()
        self.resp_lock = Lock()
        self.pragma = None

    def decrypt(self, content):
        return self.rc4.decrypt([c for c in content])

    def request(self, flow):
        if (self.pragma is not None) and ("lservlet" in flow.request.url) and ("pragma" in flow.request.headers):
            try:
                p = int(flow.request.headers["pragma"])
                if abs(p) > self.pragma:
                    self.pragma = abs(p)
                else:
                    self.pragma += 1
                if p >= 0:
                    flow.request.headers["pragma"] = str(self.pragma)
                else:
                    flow.request.headers["pragma"] = str(self.pragma * -1)
                ctx.log("[!] Set Pragma to %d" % self.pragma)
            except ValueError:
                pass

        if flow.request.content[0:4] == b"GDay":
            self.key = [None] * 5
            self.mate = None
            self.rc4_req = None
            self.rc4_resp = None
            self.gday = struct.unpack(">I", flow.request.content[4:8])[0]
            self.pragma = 1
            ctx.log.info("Found GDay %08X" % self.gday)
            return
        if self.key[0] is not None and "lservlet" in flow.request.url:
            ctx.log.debug("REQUEST:\n %s" % binascii.hexlify(flow.request.content))
            if len(flow.request.content) == 0:
                ctx.log.warn("[!] Empty message")
                return
            if not flow.request.content.endswith(b"\xf0\x01"):
                ctx.log.error("[!] Invalid request message?")
            with self.req_lock:
                flow.request.content = bytes(self.rc4_req.encrypt(flow.request.content))

    def response(self, flow):
        if b"GDay" in flow.request.content:
            self.mate = struct.unpack(">I", flow.response.content[4:8])[0]
            ctx.log.info("Found Mate %08X" % self.mate)

            self.key[0] = (self.gday >> 8) & 0xff
            self.key[1] = (self.mate >> 4) & 0xff
            self.key[2] = 0xae
            self.key[3] = (self.gday >> 16) & 0xff
            self.key[4] = (self.mate >> 12) & 0xff

            self.rc4_req = RC4()
            self.rc4_req.setKey(self.key)

            self.rc4_resp = RC4()
            self.rc4_resp.setKey(self.key)

            ctx.log("RC4 initialized with key: %s" % ''.join("%02X" % a for a in self.key))

            # Noble the handshake
            flow.response.replace("Mate", "Matf")
            return

        if self.key[0] is not None \
                and "lservlet" in flow.request.url \
                and flow.response.headers['content-type'] == "application/octet-stream":
            with self.resp_lock:
                flow.response.content = self.rc4_resp.decrypt([c for c in flow.response.content])
            if not flow.response.content.endswith(b"\xf0\x01"):
                ctx.log.error("[!] Invalid response message?")
            ctx.log.debug("RESPONSE:\n %s" % binascii.hexlify(flow.response.content))


addons = [
    OracleForms()
]
