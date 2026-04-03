"""
Bitcoin script builder utilities.

Provides low-level Bitcoin script construction following Bitcoin Core standards.
"""

import hashlib
import logging
from typing import List, Union

logger = logging.getLogger(__name__)


class Script:
    """
    Bitcoin script builder.
    
    Follows Bitcoin Core script construction standards.
    """
    
    # Bitcoin opcodes (from Bitcoin Core src/script/script.h)
    OP_0 = 0x00
    OP_FALSE = 0x00
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_1 = 0x51
    OP_TRUE = 0x51
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60
    
    # Flow control
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a
    
    # Stack
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_SWAP = 0x7c
    
    # Crypto
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf
    
    # Locktime
    OP_CHECKLOCKTIMEVERIFY = 0xb1  # BIP-65
    OP_CHECKSEQUENCEVERIFY = 0xb2  # BIP-112
    
    # Comparison
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    
    def __init__(self):
        self.script = bytearray()
    
    def push_data(self, data: Union[bytes, bytearray]) -> 'Script':
        """
        Push data onto the stack.
        
        Automatically uses the correct push opcode based on data length:
        - 0-75 bytes: Direct push (length byte + data)
        - 76-255 bytes: OP_PUSHDATA1
        - 256-65535 bytes: OP_PUSHDATA2
        - 65536+ bytes: OP_PUSHDATA4
        
        Args:
            data: Data to push
        
        Returns:
            Self for chaining
        """
        data_len = len(data)
        
        if data_len <= 75:
            # Direct push: length byte + data
            self.script.append(data_len)
            self.script.extend(data)
        elif data_len <= 0xff:
            # OP_PUSHDATA1: opcode + 1-byte length + data
            self.script.append(self.OP_PUSHDATA1)
            self.script.append(data_len)
            self.script.extend(data)
        elif data_len <= 0xffff:
            # OP_PUSHDATA2: opcode + 2-byte length (LE) + data
            self.script.append(self.OP_PUSHDATA2)
            self.script.extend(data_len.to_bytes(2, 'little'))
            self.script.extend(data)
        else:
            # OP_PUSHDATA4: opcode + 4-byte length (LE) + data
            self.script.append(self.OP_PUSHDATA4)
            self.script.extend(data_len.to_bytes(4, 'little'))
            self.script.extend(data)
        
        return self
    
    def push_int(self, n: int) -> 'Script':
        """
        Push an integer onto the stack.
        
        Uses OP_0 through OP_16 for small integers, otherwise encodes as bytes.
        
        Args:
            n: Integer to push
        
        Returns:
            Self for chaining
        """
        if n == -1:
            self.script.append(self.OP_1NEGATE)
        elif n == 0:
            self.script.append(self.OP_0)
        elif 1 <= n <= 16:
            self.script.append(self.OP_1 + n - 1)
        else:
            # Encode as minimal bytes (Bitcoin Core CScriptNum encoding)
            self.push_data(self._encode_scriptnum(n))
        
        return self
    
    def _encode_scriptnum(self, n: int) -> bytes:
        """
        Encode integer as Bitcoin script number (minimal encoding).
        
        Args:
            n: Integer to encode
        
        Returns:
            Minimal byte representation
        """
        if n == 0:
            return b''
        
        # Determine sign
        negative = n < 0
        absvalue = abs(n)
        
        # Encode as little-endian bytes
        result = []
        while absvalue:
            result.append(absvalue & 0xff)
            absvalue >>= 8
        
        # If high bit is set, add extra byte for sign
        if result[-1] & 0x80:
            result.append(0x80 if negative else 0x00)
        elif negative:
            result[-1] |= 0x80
        
        return bytes(result)
    
    def op(self, opcode: int) -> 'Script':
        """
        Add an opcode to the script.
        
        Args:
            opcode: Bitcoin opcode
        
        Returns:
            Self for chaining
        """
        self.script.append(opcode)
        return self
    
    def to_bytes(self) -> bytes:
        """
        Get script as bytes.
        
        Returns:
            Script bytes
        """
        return bytes(self.script)
    
    def to_hex(self) -> str:
        """
        Get script as hex string.
        
        Returns:
            Hex-encoded script
        """
        return self.to_bytes().hex()
    
    def __len__(self) -> int:
        return len(self.script)
    
    def __repr__(self) -> str:
        return f"Script({self.to_hex()})"


def sha256(data: bytes) -> bytes:
    """SHA256 hash"""
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    """HASH160 (SHA256 then RIPEMD160)"""
    return hashlib.new('ripemd160', sha256(data)).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """
    BIP-340 tagged hash.
    
    TaggedHash(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)
    
    Args:
        tag: Hash tag
        data: Data to hash
    
    Returns:
        Tagged hash (32 bytes)
    """
    tag_hash = sha256(tag.encode('utf-8'))
    return sha256(tag_hash + tag_hash + data)
