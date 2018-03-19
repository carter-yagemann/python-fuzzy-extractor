#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    Copyright 2018 Carter Yagemann
#
#    This file is part of fuzzy_extractor.
#
#    fuzzy_extractor is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    fuzzy_extractor is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with fuzzy_extractor.  If not, see <http://www.gnu.org/licenses/>.

"""A Python implementation of fuzzy extractor"""

__author__ = 'Carter Yagemann'
__email__ = 'yagemann@gatech.edu'
__copyright__ = 'Copyright (c) 2018 Carter Yagemann'
__license__ = 'GPLv3+'
__version__ = '0.2'
__url__ = 'https://github.com/carter-yagemann/python-fuzzy-extractor'
__download_url__ = 'https://github.com/carter-yagemann/python-fuzzy-extractor'
__description__ = 'A Python implementation of fuzzy extractor'

from math import log
from os import urandom
from hashlib import sha256
from base64 import b64encode
from struct import pack, unpack

def _xor(ba_a, ba_b):
    """Bitwise xor on two ord arrays"""
    return [ba_a[index] ^ ba_b[index] for index in range(len(ba_a))]

def _and(ba_a, ba_b):
    """Bitwise and on two ord arrays"""
    return [ba_a[index] & ba_b[index] for index in range(len(ba_a))]

class DigitalLocker(object):
    """A digital locker primitive"""

    def __init__(self):
        """Initializes a digital locker"""
        self.is_locked = False
        self.nonce = ' '
        self.sec_len = 0
        self.cipher = ' '
        self.hash_func = None

    def lock(self, key, value, hash_func=sha256, sec_len=2):
        """Locks value using key

        Keyword arguments:
        key -- the key to lock the value with.
        value -- the value to lock up.
        hash_func -- the hashing algorithm to use. It should have the methods update
        and digest (see hashlib for examples).
        sec_len -- security parameter. This is used to determine if the locker
        is unlocked successfully with accuracy (1 - 2 ^ -sec_len).
        """
        if isinstance(value, str):
            value = bytearray(value, 'utf8')

        if isinstance(key, str):
            key = bytearray(key, 'utf8')

        self.hash_func = hash_func
        self.nonce = urandom(32)

        digest = bytearray(self._digest(key))

        if len(digest) < len(value) + sec_len:
            raise ValueError('Length of value + sec_len cannot exceed hash length')

        self.sec_len = len(digest) - len(value)
        sec = bytearray(self.sec_len)
        padded_plain = value + sec
        self.cipher = _xor(digest, padded_plain)
        self.is_locked = True

    def unlock(self, key):
        """Unlocks the stored value using key

        Returns None if the key fails to decrypt the locked value.
        """
        if not self.is_locked:
            raise Exception('Cannot unlock a DigitalLocker with nothing in it')

        if isinstance(key, str):
            key = bytearray(key, 'utf8')

        digest = bytearray(self._digest(key))

        plain = _xor(digest, self.cipher)
        if plain[-self.sec_len:] != [0] * self.sec_len:
            return None

        return bytearray(plain[:-self.sec_len])

    def pack(self):
        """Packs the locker for easier storage

        Note, this can only be called when a value is locked inside the locker.

        Also note that it is the caller's responcibility to remember what hashing
        function was used and to pass this to unpack().
        """
        if not self.is_locked:
            raise Exception('Packing a locker with nothing in it is pointless')

        cipher_len = len(self.cipher)
        packed = pack('32s', self.nonce)
        packed += pack('H', self.sec_len)
        packed += pack('H', cipher_len)
        packed += pack(str(cipher_len) + 'B', *self.cipher)
        return packed

    def unpack(self, binary, hash_func=sha256):
        """Unpacks the locker

        Keyword arguments:
        binary -- The string produced by pack().
        hash_func -- The hash function that was used during lock().
        """
        self.nonce = unpack('32s', binary[:32])[0]
        self.sec_len = unpack('H', binary[32:34])[0]
        cipher_len = unpack('H', binary[34:36])[0]
        self.cipher = bytearray([binary[off] for off in range(36, 36 + cipher_len)])
        self.hash_func = hash_func
        self.is_locked = True

    def _digest(self, key):
        """Digests the nonce and key"""
        hasher = self.hash_func()
        hasher.update(self.nonce)
        hasher.update(key)
        return hasher.digest()

class FuzzyExtractor(object):
    """The most basic non-interactive fuzzy extractor"""

    def __init__(self, length, ham_err, rep_err=0.001, hash_func=sha256):
        """Initializes a fuzzy extractor

        Keyword arguments:
        length -- The length in bytes of source values and keys.
        ham_err -- Hamming error. The number of bits that can be flipped in the
        source value and still produce the same key with probability
        (1 - rep_err).
        rep_err -- Reproduce error. The probability that a source value within
        ham_err will not produce the same key (default: 0.001).
        hash_func -- Hashing function to be used by DigitalLocker (default: sha256).
        """
        self.length = length
        self.hash_func = hash_func

        # Calculate the number of helper values needed to be able to reproduce
        # keys given ham_err and rep_err. See "Reusable Fuzzy Extractors for
        # Low-Entropy Distributions" by Canetti, et al. for details.
        bits = length * 8
        const = float(ham_err) / log(bits)
        num_helpers = (bits ** const) * log(float(2) / rep_err, 2)

        # num_helpers needs to be an integer
        self.num_helpers = int(round(num_helpers))

    def generate(self, value):
        """Takes a source value and produces a key and public helper

        This method should be used once at enrollment.

        Keyword arguments:
        value -- the value to generate a key and public helper for.
        """
        if isinstance(value, str):
            value = bytearray(value, 'utf8')

        key = bytearray(urandom(self.length))
        helpers = list()
        locker = DigitalLocker()

        for _ in range(self.num_helpers):
            mask = bytearray(urandom(self.length))
            vector = _and(mask, value)
            locker.lock(bytearray(vector), key, hash_func=self.hash_func)
            helpers.append((locker.pack(), mask))

        return (key, helpers)

    def reproduce(self, value, helpers):
        """Takes a source value and a public helper and produces a key

        Given a helper value that matches and a source value that is close to
        those produced by generate, the same key will be produced.

        value -- the value to reproduce a key for.
        helpers -- the previously generated public helper.
        """
        if isinstance(value, str):
            value = bytearray(value, 'utf8')

        if self.length != len(value):
            raise ValueError('Cannot reproduce key for value of different length')

        locker = DigitalLocker()

        for locker_bin, mask in helpers:
            vector = _and(mask, value)
            locker.unpack(locker_bin, self.hash_func)
            res = locker.unlock(bytearray(vector))
            if not res is None:
                return res

        return None
