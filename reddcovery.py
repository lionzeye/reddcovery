import re
import hashlib
import base58
from pycoin.ecdsa import generator_secp256k1, public_pair_for_secret_exponent

def bytetohex(byteStr):
        return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

addresstype = [b"\x61", b"\xBD"]

databaseHandler = open("wallet.dat", "rb")
dbDump = databaseHandler.read()

privateKeyCollection=set(re.findall(b'\x70\x6F\x6F\x6C(.{52})', dbDump))

print("I found %d private keys" % len(privateKeyCollection))

for key in privateKeyCollection:
    key = key[20:]
    bytetohex(key)
    key = addresstype[1] + key + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(key).digest()).digest()[:4]
    addr = key + checksum 
    print base58.b58encode(addr)
    
databaseHandler.close()
