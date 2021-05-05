#!/usr/bin/python3

import unittest
import binascii
from tlv import *


class TestTlv(unittest.TestCase):

    def test_parse(self):
        # 1-byte tag
        data = Tlv.parse(binascii.unhexlify("100100"))
        assert(data[0x10] == binascii.unhexlify("00"))
        # 2-byte tag
        data = Tlv.parse(binascii.unhexlify("9F01021234"))
        assert(data[0x9F01] == binascii.unhexlify("1234"))
        # 3-byte tag
        data = Tlv.parse(binascii.unhexlify("BF8101021234"))
        assert(data[0xBF8101] == binascii.unhexlify("1234"))
        # 4-byte tag
        data = Tlv.parse(binascii.unhexlify("BF81FF01021234"))
        assert(data[0xBF81FF01] == binascii.unhexlify("1234"))
        # >4 byte length is not valid
        with self.assertRaises(BadTag):
            Tlv.parse(binascii.unhexlify("BF81FF8301021234"))
        # no data
        data = Tlv.parse(binascii.unhexlify("1000"))
        assert(len(data[0x10]) == 0)
        # 2-byte length
        data = Tlv.parse(binascii.unhexlify("12820101"+"00"*257))
        assert(len(data[0x12]) == 257)
        # length >4
        with self.assertRaises(BadLength):
            Tlv.parse(binascii.unhexlify("1285"))
        # incomplete data
        with self.assertRaises(UnexpectedEnd):
            data = Tlv.parse(binascii.unhexlify("9F010212"))
        # multiple tags
        data = Tlv.parse(binascii.unhexlify("9F1001318A03414243"))
        assert(data == {0x9F10:b"1",0x8A:b"ABC"})
        # recursive
        data = Tlv.parse(binascii.unhexlify("9F10088A03414243100100"), True)
        assert(data == {0x9F10:{0x8A:b"ABC",0x10:b"\x00"}})
        # leading zeroes
        data = Tlv.parse(binascii.unhexlify("00009F1001318A03414243"))
        assert(data == {0x9F10:b"1",0x8A:b"ABC"})
        # inter-element padding
        data = Tlv.parse(binascii.unhexlify("9F10013100008A03414243"))
        assert(data == {0x9F10:b"1",0x8A:b"ABC"})
        # trailing zeroes
        data = Tlv.parse(binascii.unhexlify("9F1001318A034142430000"))
        assert(data == {0x9F10:b"1",0x8A:b"ABC"})
        # recursive with padding
        data = Tlv.parse(binascii.unhexlify("009F100B008A034142430010010000"), True)
        assert(data == {0x9F10:{0x8A:b"ABC",0x10:b"\x00"}})

    def test_build(self):
        data = Tlv.build({0x9F10:{0x8A:b"ABC"}})
        assert(data == binascii.unhexlify("9F10058A03414243"))
        # tag must be integer
        with self.assertRaises(BadTag):
            Tlv.build({"ABC":"1234"})
        # value must be bytes or dict
        with self.assertRaises(BadParameter):
            Tlv.build({0x9F10:"1234"})
        # tag must be well formatted
        with self.assertRaises(BadTag):
            Tlv.build({0x6FFFFFFF:b"1234"})
        with self.assertRaises(BadTag):
            Tlv.build({0x7FFF0123:b"1234"})

if __name__ == '__main__':
    unittest.main()
