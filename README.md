# BER-TLV Package

## Summary
This is a BER-TLV (described in EMV Book 3) format encoder/decoder library for Python.
BER is Basic Encoding Rules.
TLV stands for Tag + Length + Value.
Tag is 1-4 byte long (integer) identifier.
Length is 1-4 byte integer representing value (or entire branch) size.
Value is binary data, which can also be a nested list of sub-items.
BER-TLV is a binary data storage tree, which is widely used in electonic payment industry and in EMV in particular.

## Install
pip3 install ber-tlv

## Usage
Parse TLV:
```
from ber_tlv.tlv import *
Tlv.parse(binascii.unhexlify("9F100D8A034142438A036465661001FF"), True)
>>> {40720:{138:[b'ABC',b'def'],16:b'\xff'}}
```
Build TLV:
```
from ber_tlv.tlv import *
Tlv.hexify_bytes(Tlv.build({0x9F10:{0x8A:[b"ABC",b"def"],0x10:b"\xff"}}))
>>> "9F100D8A034142438A036465661001FF"
```

## Technical description
Below is a brief technical description of BER-TLV format.
### Tag field
Tag has variable size of 1-4 bytes.
If first tag byte, bits 1-5 are set to 1, there are more tag bytes follow. In subsequent bytes, bit 8 indicates if this is a last byte. Other bits identify unique tag number.
### Length field
Length field has variable size of 1-4 bytes.
When bit b8 of the most significant byte of the length field is set to 0, the length field consists of only one byte. Bits b7 to b1 code the number of bytes of the value field. The length field is within the range 1 to 127.When bit b8 of the most significant byte of the length field is set to 1, the subsequent bits b7 to b1 of the most significant byte code the number of subsequent bytes in the length field. The subsequent bytes code an integer representing the number of bytes in the value field.
### Value field
Value is binary bytes array of specified length. Value may represent recursive sub-tree (branch).
### Padding
Before, between, or after TLV-coded data objects, zero bytes without any meaning may occur (for example, due to erased or modified TLV-coded data objects).

