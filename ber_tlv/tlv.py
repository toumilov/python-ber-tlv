#!/usr/bin/python3

import binascii


class BadTag(Exception):
    def __init__(self, path: list):
        self.txt = str(path)

    def __str__(self) -> str:
        return "BadTag({})".format(self.txt)

class BadLength(Exception):
    def __init__(self, path: list):
        self.txt = str(path)

    def __str__(self) -> str:
        return "BadLength({})".format(self.txt)

class BadParameter(Exception):
    def __init__(self, path: list):
        self.txt = str(path)

    def __str__(self) -> str:
        return "BadParameter({})".format(self.txt)

class UnexpectedEnd(Exception):
    def __init__(self, path: list):
        self.txt = str(path)

    def __str__(self) -> str:
        return "UnexpectedEnd({})".format(self.txt)

class Tlv:
    class Parser:
        def __init__(self, data: bytes, path: list, offset: int):
            self.path = path
            self.data = data
            self.offset = offset
            self.pos = 0
            self.MultiOctetTagMask = 0x1F
            self.MoreOctetMask = 0x80
            # states
            self.Start = 0
            self.TagStart = 1
            self.Tag = 2
            self.LenStart = 3
            self.Len = 4
            self.Data = 5
            self.End = 6

        def get_offset(self):
            return self.offset + self.pos

        def next_byte(self):
            if len(self.data) <= self.pos:
                return None
            ret = self.data[self.pos]
            self.pos += 1
            return ret

        def next(self):
            tag = 0
            tag_len = 1
            size = 0
            size_len = 0
            data = bytearray()
            state = self.Start
            while state != self.End:
                byte = self.next_byte()
                if byte == None and state != self.Start:
                    raise UnexpectedEnd("{} offset: {}".format(self.path, self.get_offset()))
                if state == self.Start:
                    if byte == 0x00:
                        continue
                    state = self.TagStart
                if state == self.TagStart:
                    if byte is None:
                        return None
                    tag = byte
                    if ( byte & self.MultiOctetTagMask ) == self.MultiOctetTagMask:
                        state = self.Tag
                    else:
                        state = self.LenStart
                elif state == self.Tag:
                    if tag_len >= 4:
                        raise BadTag("Tag is too long, offset {}".format(self.get_offset()))
                    tag_len += 1
                    tag = ( tag << 8 ) | byte
                    if ( byte & self.MoreOctetMask ) == self.MoreOctetMask:
                        state = self.Tag
                    else:
                        state = self.LenStart
                elif state == self.LenStart:
                    if (byte & self.MoreOctetMask) == self.MoreOctetMask:
                        size_len = (byte ^ self.MoreOctetMask)
                        if size_len > 4:
                            raise BadLength("Tag length is too large, offset {}".format(self.get_offset()))
                        state = self.Len
                    else:
                        size = byte
                        if size > 0:
                            state = self.Data
                        else:
                            state = self.End
                elif state == self.Len:
                    size = (size << 8) | byte
                    size_len -= 1
                    if size_len == 0:
                        if size > 0:
                            state = self.Data
                        else:
                            state = self.End
                elif state == self.Data:
                    data.append(byte)
                    size -= 1
                    if size <= 0:
                        state = self.End
            return (tag, bytes(data))

        @staticmethod
        def parse(data, recursive, path, verbose, offset) -> dict:
            tlv = Tlv.Parser(data, path, offset)
            res = {}
            def __insert(tag, value):
                if tag in res: # Duplicate tags
                    if isinstance(res[tag], list) == False:
                        tmp = res[tag]
                        res[tag] = list()
                        res[tag].append(tmp)
                    res[tag].append(value)
                else:
                    res[tag] = value
            while True:
                t = tlv.next()
                if t is None:
                    break
                (tag, value) = t
                if recursive == True and len(value) > 2:
                    try:
                        path.append(tag)
                        tmp = Tlv.Parser.parse(value, recursive, path, verbose, tlv.get_offset()-len(value))
                        if tmp == {}:
                            __insert(tag, value)
                        else:
                            __insert(tag, tmp)
                        path.pop()
                    except Exception as e:
                        if verbose:
                            print(str(e))
                        path.pop()
                        __insert(tag, value)
                else:
                    __insert(tag, value)
            return res

    class Builder:
        @staticmethod
        def __build_tag(tag: int) -> bytearray:
            out = bytearray()
            tag_bytes = bytearray()
            for b in tag.to_bytes(4, byteorder="big"):
                if b == 0:
                    continue
                tag_bytes.append(b)
            if len(tag_bytes) > 1 and (tag_bytes[0] & 0x1f) != 0x1f:
                raise BadTag(str(tag))
            out.append(tag_bytes[0])
            next_expected = (tag_bytes[0] & 0x1f) == 0x1f
            for i in tag_bytes[1:]:
                if not next_expected:
                    raise BadTag(str(tag))
                next_expected = (i & 0x80) == 0x80
                out.append(i)
            return out

        @staticmethod
        def __build_len(size: int) -> bytearray:
            out = bytearray()
            if size >= 0x80:
                num_bytes = 1
                l = size
                for _ in range(3):
                    l = l >> 8
                    if l == 0:
                        break
                    num_bytes += 1
                out.append(num_bytes | 0x80)
                for i in range(num_bytes, 0, -1):
                    out.append((size >> (8 * (i - 1))) & 0xFF)
            else:
                out.append(size)
            return out

        @staticmethod
        def build(data: dict) -> bytes:
            out = bytearray()
            for tag, value in data.items():
                if not isinstance(tag, int):
                    raise BadTag(type(tag).__name__)
                if value is None:
                    value = bytes()
                elif isinstance(value, dict):
                    value = Tlv.build(value)
                elif isinstance(value, list):
                    for i in value:
                        out += Tlv.Builder.__build_tag(tag)
                        if isinstance(i, dict):
                            buf = Tlv.build(i)
                            out += Tlv.Builder.__build_len(len(buf))
                            out += buf
                        elif isinstance(i, bytes):
                            out += Tlv.Builder.__build_len(len(i))
                            out += i
                        else:
                            raise BadParameter(type(value).__name__)
                    continue
                elif not isinstance(value, bytes):
                    raise BadParameter(type(value).__name__)
                # Tag
                out += Tlv.Builder.__build_tag(tag)
                # Length
                out += Tlv.Builder.__build_len(len(value))
                # Value
                out += value
            return bytes(out)

    @staticmethod
    def hexify_bytes(msg: bytes) -> str:
        return "".join("{:02X}".format(x) for x in msg)

    @staticmethod
    def parse(data: bytes, recursive: bool = False, verbose: bool = False) -> dict:
        path = list()
        return Tlv.Parser.parse(data, recursive, path, verbose, 0)

    @staticmethod
    def build(data: dict) -> bytes:
        return Tlv.Builder.build(data)
