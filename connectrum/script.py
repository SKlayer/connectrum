from bitcoinb58 import b58decode, b58encode
from hashlib import sha256
import hashlib
import binascii


def dblsha(b):
    return sha256(sha256(b).digest()).digest()


def ripemd160(inp):
    h = hashlib.new('ripemd160')
    h.update(inp)
    return h.digest()


WitnessMagic = b'\xaa\x21\xa9\xed'


def _Address2PKH(addr):
    try:
        addr = b58decode(addr, 25)
    except:
        return None

    if addr is None:
        return None
    ver = addr[0]
    cksumA = addr[-4:]
    cksumB = dblsha(addr[:-4])[:4]
    if cksumA != cksumB:
        return None
    return (ver, addr[1:-4])


def _PKH2Address(ver, addr):
    addr = addr[3:-2]
    ver = int(ver).to_bytes(length=1, byteorder="little", signed=False)

    cksumB = dblsha(ver + addr)[:4]
    px = ""
    if ver == b"\x00":
        px = "1"
    return px + b58encode(ver + addr + cksumB)

class BitcoinScript:
    @classmethod
    def toAddress(cls,addr):
        d = _Address2PKH(addr)
        if not d:
            raise ValueError('invalid address')
        (ver, pubkeyhash) = d
        if ver == 35 or ver == 111 or ver == 0:
            return b'\x76\xa9\x14' + pubkeyhash + b'\x88\xac'
        elif ver == 5 or ver == 196:
            return b'\xa9\x14' + pubkeyhash + b'\x87'
        raise ValueError('invalid address version')

    @classmethod
    def commitment(cls, commitment):
        clen = len(commitment)
        if clen > 0x4b:
            raise NotImplementedError
        return b'\x6a' + bytes((clen,)) + commitment


def fch2btc(addr):
    pkh =BitcoinScript.toAddress(addr)
    return _PKH2Address(0, pkh)

def btc2fch(addr):
    pkh =BitcoinScript.toAddress(addr)

    return _PKH2Address(35, pkh)



if __name__ == '__main__':
    o = fch2btc("FMHuHuKmWQHQx3ZxmaeHnrRsPrLYRkUat4")
    print(o)
    o = btc2fch("1GTnq6tgf64kKsgvutz8pTuLNCKXXCzXDK")
    print(o)
