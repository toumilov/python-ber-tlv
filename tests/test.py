#!/usr/bin/python3

import unittest
import binascii
from tlv import *


class TestTlv(unittest.TestCase):

    def test_parse(self):
        # 1-byte tag
        data = Tlv.parse(binascii.unhexlify("100100"))
        assert(data == [(0x10, b"\x00")])
        # 2-byte tag
        data = Tlv.parse(binascii.unhexlify("9F01021234"))
        assert(data == [(0x9F01, b"\x12\x34")])
        # 3-byte tag
        data = Tlv.parse(binascii.unhexlify("BF8101021234"))
        assert(data == [(0xBF8101, b"\x12\x34")])
        # 4-byte tag
        data = Tlv.parse(binascii.unhexlify("BF81FF01021234"))
        assert(data == [(0xBF81FF01, b"\x12\x34")])
        # >4 byte length is not valid
        with self.assertRaises(BadTag):
            Tlv.parse(binascii.unhexlify("BF81FF8301021234"))
        # no data
        data = Tlv.parse(binascii.unhexlify("1000"))
        assert(data == [(0x10, b"")])
        # 2-byte length
        data = Tlv.parse(binascii.unhexlify("12820101"+"00"*257))
        tag, value = data[0]
        assert(tag == 0x12)
        assert(len(value) == 257)
        assert(value == binascii.unhexlify("00"*257))
        # length >4
        with self.assertRaises(BadLength):
            Tlv.parse(binascii.unhexlify("1285"))
        # incomplete data
        with self.assertRaises(UnexpectedEnd):
            data = Tlv.parse(binascii.unhexlify("9F010212"))
        # multiple tags
        data = Tlv.parse(binascii.unhexlify("9F1001318A03414243"))
        assert(data == [(0x9F10,b"1"),(0x8A,b"ABC")])
        # recursive
        data = Tlv.parse(binascii.unhexlify("9F10088A03414243100100"), True)
        assert(data == [(0x9F10,[(0x8A,b"ABC"),(0x10,b"\x00")])])
        # leading zeroes
        data = Tlv.parse(binascii.unhexlify("00009F1001318A03414243"))
        assert(data == [(0x9F10,b"1"),(0x8A,b"ABC")])
        # inter-element padding
        data = Tlv.parse(binascii.unhexlify("9F10013100008A03414243"))
        assert(data == [(0x9F10,b"1"),(0x8A,b"ABC")])
        # trailing zeroes
        data = Tlv.parse(binascii.unhexlify("9F1001318A034142430000"))
        assert(data == [(0x9F10,b"1"),(0x8A,b"ABC")])
        # recursive with padding
        data = Tlv.parse(binascii.unhexlify("009F100B008A034142430010010000"), True)
        assert(data == [(0x9F10,[(0x8A,b"ABC"),(0x10,b"\x00")])])
        # Unexpected end in recursion
        data = Tlv.parse(binascii.unhexlify("1001018A079F1002414210019F110131"), True)
        assert(data == [(0x10,b"\x01"),(0x8a,b"\x9F\x10\x02\x41\x42\x10\x01"),(0x9F11,b"1")])
        # Duplicate tags
        data = Tlv.parse(binascii.unhexlify("9F01108A034142438A034445468A04100201021101FF"), True)
        assert(data == [(0x9F01,[(0x8A,b"ABC"),(0x8A,b'DEF'),(0x8A,[(0x10,b"\x01\x02")])]),(0x11,b"\xff")])
        # Recursion based on tag constructed type
        data = Tlv.parse(binascii.unhexlify("7F100DF303414243F4038A0135100100"))
        assert(data == [(0x7F10,[(0xF3,b"ABC"),(0xF4,[(0x8A,b"5")]),(0x10,b"\x00")])])
        data = Tlv.parse(binascii.unhexlify("7F100DF303414243F4038A0135100100"), None)
        assert(data == [(0x7F10,[(0xF3,b"ABC"),(0xF4,[(0x8A,b"5")]),(0x10,b"\x00")])])
        # Forced recursion
        data = Tlv.parse(binascii.unhexlify("7F100DF303414243D4038A0135100100"), True)
        assert(data == [(0x7F10,[(0xF3,b"ABC"),(0xD4,[(0x8A,b"5")]),(0x10,b"\x00")])])
        # No recursion
        data = Tlv.parse(binascii.unhexlify("7F100DF303414243F4038A0135100100"), False)
        assert(data == [(0x7F10,b"\xF3\x03\x41\x42\x43\xF4\x03\x8A\x01\x35\x10\x01\x00")])

    def test_build(self):
        # Empty dict
        data = Tlv.build({})
        assert(data == b"")
        # Nested items
        data = Tlv.build({0x9F10:{0x8A:b"ABC"}})
        assert(data == binascii.unhexlify("9F10058A03414243"))
        # Nested items: empty list
        data = Tlv.build({0x9F10:{0x8A:b"ABC",0x8B:[]}})
        assert(data == binascii.unhexlify("9F10078A034142438B00"))
        # Nested items: list
        data = Tlv.build({0x9F10:[(0x8A,b"ABC"),(0x8B,{0x10:b"\xf0\x0d"})]})
        assert(data == binascii.unhexlify("9F100b8A034142438B041002f00d"))
        # Empty tag
        data = Tlv.build({0x9F10:{0x8A:None}})
        assert(data == binascii.unhexlify("9F10028A00"))
        # Duplicate tags (list of tags) - ordering preserved
        data = Tlv.build([(0x9F01,[(0x8A,b'\x01'),(0x8B,b"ABC"),(0x8A,b"\x02"),(0x8B,b"DEF"),(0x10,[(0x11,b"\x01\x02")])]),(0x11,b"\xff")])
        assert(data == binascii.unhexlify("9f01168a01018b034142438a01028b034445461004110201021101ff"))
        # tag must be integer
        with self.assertRaises(BadTag):
            Tlv.build({0x8A:[(0x8B,b"12"),("8C",b"34")]})
        # value must be bytes, dict or list
        with self.assertRaises(BadParameter):
            Tlv.build({0x9F10:"1234"})
        # tag must be well formatted
        with self.assertRaises(BadTag):
            Tlv.build({0x6FFFFFFF:b"1234"})
        with self.assertRaises(BadTag):
            Tlv.build({0x7FFF0123:b"1234"})

    def test_hexify(self):
        assert(Tlv.hexify_bytes(b"\x01\x23\x45\x67\x89\xab\xcd\xef") == "0123456789ABCDEF")

    def test_tags(self):
        assert(Tag.tagClass(0x1f10) == Tag.UNIVERSAL)
        assert(Tag.isConstructed(0x1f10) == False)
        assert(Tag.tagClass(0x3f10) == Tag.UNIVERSAL)
        assert(Tag.isConstructed(0x3f10) == True)
        assert(Tag.tagClass(0x5f10) == Tag.APPLICATION)
        assert(Tag.isConstructed(0x5f10) == False)
        assert(Tag.tagClass(0x7f10) == Tag.APPLICATION)
        assert(Tag.isConstructed(0x7f10) == True)
        assert(Tag.tagClass(0x9f10) == Tag.CONTEXT_SPECIFIC)
        assert(Tag.isConstructed(0x9f10) == False)
        assert(Tag.tagClass(0xbf10) == Tag.CONTEXT_SPECIFIC)
        assert(Tag.isConstructed(0xbf10) == True)
        assert(Tag.tagClass(0xdf10) == Tag.PRIVATE)
        assert(Tag.isConstructed(0xdf10) == False)
        assert(Tag.tagClass(0xff10) == Tag.PRIVATE)
        assert(Tag.isConstructed(0xff10) == True)
        assert(Tag.tagClass(0) == Tag.UNIVERSAL)
        assert(Tag.isConstructed(0) == False)

if __name__ == '__main__':
    unittest.main()
