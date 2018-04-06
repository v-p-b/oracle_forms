import binascii
import struct
from threading import Lock
from mitmproxy import ctx
import requests
import time
import argparse

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

    def encrypt(self,inputBytes):
        ##Encrypt input string returning a byte list
        
        return [p ^ self.byteGenerator() for p in inputBytes]

    def decrypt(self,inputByteList):
        ##Decrypt input byte list returning a string
        return bytes([c ^ self.byteGenerator() for c in inputByteList])

    #def string_to_list(self,inputString):
    #    ##Convert a string into a byte list
    #    return [ord(c) for c in inputString]


class OracleForms:
    def __init__(self, maxwait=-1):
        self.gday=None
        self.mate=None
        self.key=[None]*5
        self.rc4_req=None
        self.rc4_resp=None
        self.req_lock=Lock()
        self.resp_lock=Lock()
        self.pragma=None
        self.max_wait=int(maxwait)
        self.total_wait=0
        wait_msg="unlimited"
        if self.max_wait>=0:
            wait_msg="%d ms" % (self.max_wait)
        ctx.log("[+] Maximum wait time: %s" % (wait_msg))

    def decrypt(self,content):
        return self.rc4.decrypt([c for c in content])

    def request(self, flow):
        flow.request.http_version="HTTP/1.0" # Workaround for MitMproxy bug #1721
        
        if (self.pragma!=None) and ("lservlet" in flow.request.url) and ("pragma" in flow.request.headers):
            try:
                p=int(flow.request.headers["pragma"])
                if abs(p)>self.pragma:
                    self.pragma=abs(p)
                else:
                    self.pragma+=1
                if p>=0:
                    flow.request.headers["pragma"]=str(self.pragma)
                else:
                    flow.request.headers["pragma"]=str(self.pragma*-1)
                ctx.log("[!] Set Pragma to %d" % self.pragma)
            except ValueError:
                pass
        
        if flow.request.content[0:4]==b"GDay":
            self.key=[None]*5
            self.mate=None
            self.rc4_req=None
            self.rc4_resp=None
            self.gday=struct.unpack(">I",flow.request.content[4:8])[0]
            self.pragma=1
            ctx.log("Found GDay %X" % self.gday)
            return
        if self.key[0]!=None and "lservlet" in flow.request.url:
            ctx.log("REQUEST:\n %s" % binascii.hexlify(flow.request.content))
            if len(flow.request.content)==0:
                ctx.log("[!] Empty message")
                return
            if not flow.request.content.endswith(b"\xf0\x01"):
                ctx.log("[!] Invalid request message?")
            with self.req_lock:
                flow.request.content=bytes(self.rc4_req.encrypt(flow.request.content))
            #ctx.log(repr(self.rc4_req.decrypt([c for c in flow.request.content])))

    def response(self, flow):
        
        if "frmall.jar" in flow.request.url:
            ctx.log("Serving patched frmall.jar")
            patched=open("/tmp/frmall.jar","rb").read()
            flow.response.content=patched
            flow.response.headers["content-length"] = str(len(patched))
            flow.response.status_code=200
            return
        
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
        if b"ifError:11/" in flow.response.content:
            with self.resp_lock:
                with self.req_lock: # We don't want any inteference with other requests
                    wait=int(flow.response.content.split(b"/")[1])
                    headers=flow.request.headers
                    self.pragema=abs(self.pragma) # making sure Pragma is not negative
                    while True:
                        self.total_wait += wait
                        if self.max_wait >= 0 and self.total_wait > self.max_wait: 
                            break
                        ctx.log("[!] Handling ifError:11 - %d ms timeout" % wait)
                        time.sleep(wait / 1000.0)
                        self.pragma += 1 
                        headers["Pragma"] = "%d" % (-1*self.pragma)
                        headers["Content-Length"] = "0"
                        r=requests.post(flow.request.url, headers=headers, data=None)
                        if r.headers['content-type'] == "text/plain":
                            wait=int(r.content.split(b"/")[1])
                        else:
                            flow.response.content=self.rc4_resp.decrypt([c for c in r.content])
                            flow.response.headers["Content-Type"]="application/octet-stream"
                            flow.response.headers["Content-Length"]=str(len(flow.response.content))
                            self.total_wait = 0
                            ctx.log("[+] Timeout handled")
                            break
            return # Response already decrypted, we can return now

        if self.key[0]!=None and "lservlet" in flow.request.url and flow.response.headers['content-type']=="application/octet-stream":
            with self.resp_lock:
                self.total_wait = 0
                flow.response.content=self.rc4_resp.decrypt([c for c in flow.response.content])
            if not flow.response.content.endswith(b"\xf0\x01"):
                ctx.log("[!] Invalid response message?")
            ctx.log("RESPONSE:\n %s" % binascii.hexlify(flow.response.content))

def start():
    parser = argparse.ArgumentParser()
    parser.add_argument("--maxwait", type=int, default=-1)
    args = parser.parse_args()
    return OracleForms(maxwait=args.maxwait)
