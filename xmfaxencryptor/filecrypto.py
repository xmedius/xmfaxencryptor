import os
import struct
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


KEY_BYTES_256 = 32
_AES_BLOCK_SIZE_BYTES = 16

_HEADER_MIN_SIZE_VERSION_1 = 56
_SEGMENT_HEADER_SIZE = 24
_HASH_MAX_DATA_SIZE = 256
_HASH_SALT_SIZE = 32

XX_CIPHER_NONE = 0
XX_CIPHER_AES256CBC = 1
XX_CIPHER_AES256CTR = 2

XX_CIPHER_AES256CTR_NAME = 'aes-256-ctr'

def _assert_equal(expected, actual, what):
    if expected != actual:
        raise RuntimeError(what + ': expected=' + str(expected) + ' actual=' + str(actual))

def _write_int4(f, value):
    res = f.write(struct.pack('=i', value))
    _assert_equal(4, res, '_write_int4')

def _write_int8(f, value):
    res = f.write(struct.pack('=q', value))
    _assert_equal(8, res, '_write_int8')

def _read_int4(f):
    value = f.read(4)
    _assert_equal(4, len(value), '_read_int4')
    return struct.unpack('=i', value)[0]

def _read_int8(f):
    value = f.read(8)
    _assert_equal(8, len(value), '_read_int8')
    return struct.unpack('=q', value)[0]

def gen_random_key_256():
    return os.urandom(KEY_BYTES_256)


class AES256CTRCipher(object):
    def __init__(self, key):
        self.set_key(key)

    def set_key(self, key):
        if key and len(key) != KEY_BYTES_256:
            raise RuntimeError('Invalid key size')
        self.key = key

    def id(self):
        return XX_CIPHER_AES256CTR

    def name(self):
        return XX_CIPHER_AES256CTR_NAME

    def iv_size(self):
        return _AES_BLOCK_SIZE_BYTES

    def encrypted_size(self, raw):
        return len(raw)

    def encrypt(self, salt, raw):
        if not self.key:
            raise RuntimeError('key not set')
        backend = default_backend()
        iv = os.urandom(self.iv_size())
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=backend)
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(salt) + encryptor.update(raw) + encryptor.finalize() if salt else encryptor.update(raw) + encryptor.finalize()
        return (iv, encrypted)

    def decrypt(self, iv, enc):
        if not self.key:
            raise RuntimeError('key not set')
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(enc) + decryptor.finalize()
        return decrypted

def _get_cipher(id, key=None):
    if id == XX_CIPHER_AES256CTR:
        return AES256CTRCipher(key)
    raise RuntimeError('_get_cipher: unknown cipher id ' + str(id))

def _get_cipher_by_name(name, key=None):
    if name.lower() == XX_CIPHER_AES256CTR_NAME:
        return _get_cipher(XX_CIPHER_AES256CTR, key)
    raise RuntimeError('_get_cipher_by_name: unknown cipher ' + name)


class _FileHeader:
    def __init__(self):
        self.bom = bytes(b'\x58\x58\x19\x00')
        self.version = 1
        self.cipher_id = XX_CIPHER_AES256CTR
        self.key_id = ''
        self.hash_first_segment = bytes(32)
        self.first_segment_offset = 0

    @staticmethod
    def read_from_file(f):
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if file_size == 0:
            return _FileHeader()
        elif file_size < _HEADER_MIN_SIZE_VERSION_1:
            raise RuntimeError('Invalid format: min size')
        f.seek(0)
        header = _FileHeader()
        bom = f.read(4)
        _assert_equal(4, len(bom), '_FileHeader.read_from_file')
        if bom != header.bom:
            raise RuntimeError('Invalid format: bom')
        version = _read_int4(f)
        if version != header.version:
            raise RuntimeError('Invalid format: version')
        header.cipher_id = _read_int4(f)
        key_id_len = _read_int4(f)
        if key_id_len > 0:
            if file_size < _HEADER_MIN_SIZE_VERSION_1 + key_id_len:
                raise RuntimeError('Invalid format: min size with key')
            header.key_id = f.read(key_id_len).decode(encoding='utf-8')
        header.hash_first_segment = f.read(32)
        _assert_equal(32, len(header.hash_first_segment), '_FileHeader.read_from_file')
        header.first_segment_offset = _read_int8(f)
        return header

    def size(self):
        return _HEADER_MIN_SIZE_VERSION_1 + len(self.key_id.encode(encoding='utf-8'))

    def write_to(self, f):
        res = f.write(self.bom)
        _assert_equal(4, res, '_FileHeader.write_to')
        _write_int4(f, self.version)
        _write_int4(f, self.cipher_id)
        key_id_bytes = self.key_id.encode(encoding='utf-8')
        len_key_id_bytes = len(key_id_bytes)
        _write_int4(f, len_key_id_bytes)
        res = f.write(key_id_bytes)
        _assert_equal(len_key_id_bytes, res, '_FileHeader.write_to')
        res = f.write(self.hash_first_segment)
        _assert_equal(32, res, '_FileHeader.write_to')
        _write_int8(f, self.first_segment_offset)


class _SegmentHeader:
    def __init__(self):
        self.data_size = 0
        self.segment_size = 0
        self.data_offset = 0
        self.next_segment_offset = 0

    @staticmethod
    def _read_from_file_at_offset(f, offset):
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if file_size < offset + _SEGMENT_HEADER_SIZE:
            raise RuntimeError('Invalid format: segment size')
        f.seek(offset)
        header = _SegmentHeader()
        header.data_size = _read_int4(f)
        header.segment_size = _read_int4(f)
        header.data_offset = _read_int8(f)
        header.next_segment_offset = _read_int8(f)
        return header

    @staticmethod
    def read_all_from_file(f, first_segment_offset):
        offset = first_segment_offset
        dummy_header = _SegmentHeader()
        dummy_header.next_segment_offset = offset
        headers = [dummy_header,]
        while offset != 0:
            header = _SegmentHeader._read_from_file_at_offset(f, offset)
            headers.append(header)
            offset = header.next_segment_offset
        return headers

    def write_to(self, f):
        _write_int4(f, self.data_size)
        _write_int4(f, self.segment_size)
        _write_int8(f, self.data_offset)
        _write_int8(f, self.next_segment_offset)


class FileDecryptor:
    def __init__(self, filename):
        self.file = open(filename, 'rb')
        self.file_header = _FileHeader.read_from_file(self.file)
        self.segment_headers = _SegmentHeader.read_all_from_file(self.file, self.file_header.first_segment_offset)
        self.cipher = _get_cipher(self.file_header.cipher_id)

    def decrypted_size(self):
        size = 0
        for header in self.segment_headers:
            size += header.data_size
        return size

    def key_id(self):
        return self.file_header.key_id

    def cipher_id(self):
        return self.cipher.name()

    def set_key_and_validate(self, key):
        self.cipher.set_key(key)
        if len(self.segment_headers) > 1:
            header = self.segment_headers[1]
            self.file.seek(header.data_offset)
            iv_size = self.cipher.iv_size()
            iv = self.file.read(iv_size)
            _assert_equal(iv_size, len(iv), 'FileDecryptor.set_key_and_validate')
            enc = self.file.read(header.segment_size - iv_size)
            _assert_equal(header.segment_size - iv_size, len(enc), 'FileDecryptor.set_key_and_validate')
            clear = self.cipher.decrypt(iv, enc)
            validation_hash = hashlib.sha256(clear[0:_HASH_MAX_DATA_SIZE+_HASH_SALT_SIZE]).digest()
            if validation_hash != self.file_header.hash_first_segment:
                self.cipher.set_key(None)
                raise RuntimeError('Invalid key')

    def decrypt(self, out_stream):
        iv_size = self.cipher.iv_size()
        first_segment = True
        for header in self.segment_headers[1:]:
            self.file.seek(header.data_offset)
            iv = self.file.read(iv_size)
            _assert_equal(iv_size, len(iv), 'FileDecryptor.decrypt')
            enc = self.file.read(header.segment_size - iv_size)
            _assert_equal(header.segment_size - iv_size, len(enc), 'FileDecryptor.decrypt')
            clear = self.cipher.decrypt(iv, enc)
            if first_segment:
                if len(clear) >= _HASH_SALT_SIZE:
                    clear = clear[_HASH_SALT_SIZE:]
                first_segment = False
            res = out_stream.write(clear)
            _assert_equal(len(clear), res, 'FileDecryptor.decrypt')

    def close(self):
        self.file.close()


class FileEncryptor:
    def __init__(self, input_stream, key_id, key, cipher_id=XX_CIPHER_AES256CTR_NAME, segment_size=256*1024):
        self.input_stream = input_stream
        self.key_id = key_id
        self.cipher = _get_cipher_by_name(cipher_id, key)
        self.segment_size = segment_size
        self.offset = 0
        self.file_header_written = False
        self.previous_segment_header = None
        self.out_stream = None

    def encrypt(self, out_stream):
        self.out_stream = out_stream
        if type(self.input_stream) is FileDecryptor:
            self.input_stream.decrypt(self)
        else:
            while True:
                clear = self.input_stream.read(self.segment_size)
                if not clear:
                    break
                self.write(clear)
        if self.previous_segment_header:
            self.previous_segment_header.next_segment_offset = 0
            self.previous_segment_header.write_to(self.out_stream)

    def write(self, clear):
        if clear:
            salt = None if self.file_header_written else os.urandom(_HASH_SALT_SIZE)
            (iv, enc) = self.cipher.encrypt(salt, clear)
            segment_header = _SegmentHeader()
            segment_header.data_size = len(clear)
            segment_header.segment_size = len(iv) + len(enc)

            if not self.file_header_written:
                header = _FileHeader()
                header.cipher_id = self.cipher.id()
                header.key_id = self.key_id
                header.hash_first_segment = hashlib.sha256(salt + clear[0:_HASH_MAX_DATA_SIZE]).digest()
                header.first_segment_offset = header.size() + segment_header.segment_size
                header.write_to(self.out_stream)
                self.file_header_written = True
                self.offset = header.size()
            else:
                self.previous_segment_header.next_segment_offset = self.offset + _SEGMENT_HEADER_SIZE + segment_header.segment_size
                self.previous_segment_header.write_to(self.out_stream)
                self.offset += _SEGMENT_HEADER_SIZE

            segment_header.data_offset = self.offset
            res = self.out_stream.write(iv)
            _assert_equal(len(iv), res, 'FileEncryptor.encrypt')
            res = self.out_stream.write(enc)
            _assert_equal(len(enc), res, 'FileEncryptor.encrypt')
            self.offset += segment_header.segment_size
            self.previous_segment_header = segment_header
            return len(clear)
        else:
            return 0
