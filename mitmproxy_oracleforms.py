import struct
from mitmproxy import ctx

class RC4:
    def __init__(self):
        self.state = [None] * 256
        self.p = self.q = None

    def setKey(self,key):
        ##RC4 Key Scheduling Algorithm
        #key=self.string_to_list(k)
        self.state = [n for n in range(256)]
        self.p = self.q = j = 0
        for i in range(256):
            if len(key) > 0:
                j = (j + self.state[i] + key[i % len(key)]) % 256
            else:
                j = (j + self.state[i]) % 256
            self.state[i], self.state[j] = self.state[j], self.state[i]

    def byteGenerator(self):
        ##RC4 Pseudo-Random Generation Algorithm
        self.p = (self.p + 1) % 256
        self.q = (self.q + self.state[self.p]) % 256
        self.state[self.p], self.state[self.q] = self.state[self.q], self.state[self.p]
        return self.state[(self.state[self.p] + self.state[self.q]) % 256]

    def encrypt(self,inputString):
        ##Encrypt input string returning a byte list
        
        return [ord(p) ^ self.byteGenerator() for p in inputString]

    def decrypt(self,inputByteList):
        ##Decrypt input byte list returning a string
        return "".join([chr(c ^ self.byteGenerator()) for c in inputByteList])

    #def string_to_list(self,inputString):
    #    ##Convert a string into a byte list
    #    return [ord(c) for c in inputString]


class OracleForms:
    def __init__(self):
        self.gday=None
        self.mate=None
        self.key=[None]*5
        self.rc4_req=None
        self.rc4_resp=None

    def decrypt(self,content):
        return self.rc4.decrypt([c for c in content])

    def request(self, flow):
        flow.request.http_version="HTTP/1.0" # Workaround for MitMproxy bug #1721

        if flow.request.content[0:4]==b"GDay":
            self.gday=struct.unpack(">I",flow.request.content[4:8])[0]
            ctx.log("Found GDay %X" % self.gday)
            return
        if self.key[0]!=None and "lservlet" in flow.request.url:
            
            ctx.log(repr(self.rc4_req.decrypt([c for c in flow.request.content])))

    def response(self, flow):
        """
        if "frmall.jar" in flow.request.url:
            patched=open("/tmp/frmall.jar","rb").read()
            flow.response.content=patched
            flow.response.headers["content-length"] = str(len(patched))
            flow.response.status_code=200
            return
        """
        if b"GDay" in flow.request.content:
            self.mate=struct.unpack(">I",flow.response.content[4:8])[0]
            ctx.log("Found Mate %s" % repr(flow.response.raw_content))
            #Found GDay! be862007
            #Found Mate! 000055f0
            #RC4 Key: 205fae8605
            self.key[0]=(self.gday >> 8) & 0xff
            self.key[1]=(self.mate >> 4) & 0xff
            self.key[2]=0xae
            self.key[3]=(self.gday >> 16) & 0xff
            self.key[4]=(self.mate >> 12) & 0xff
            
            self.rc4_req=RC4()
            self.rc4_req.setKey(self.key)

            self.rc4_resp=RC4()
            self.rc4_resp.setKey(self.key)

            ctx.log("RC4 initialized with key: %s" % (repr(self.key)))
            return
        if self.key[0]!=None and "lservlet" in flow.request.url:
            ctx.log(repr(self.rc4_resp.decrypt([c for c in flow.request.content])))

def start():
    return OracleForms()