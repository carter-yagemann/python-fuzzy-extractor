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
__version__ = '0.3'
__url__ = 'https://github.com/carter-yagemann/python-fuzzy-extractor'
__download_url__ = 'https://github.com/carter-yagemann/python-fuzzy-extractor'
__description__ = 'A Python implementation of fuzzy extractor'

from math import log
from os import urandom
from struct import pack, unpack
from fastpbkdf2 import pbkdf2_hmac
import numpy as np

class FuzzyExtractor(object):
    """The most basic non-interactive fuzzy extractor"""

    def __init__(self, length, ham_err, rep_err=0.001, **locker_args):
        """Initializes a fuzzy extractor

        :param length: The length in bytes of source values and keys.
        :param ham_err: Hamming error. The number of bits that can be flipped in the
            source value and still produce the same key with probability (1 - rep_err).
        :param rep_err: Reproduce error. The probability that a source value within
            ham_err will not produce the same key (default: 0.001).
        :param locker_args: Keyword arguments to pass to the underlying digital lockers.
            See parse_locker_args() for more details.
        """
        self.parse_locker_args(**locker_args)
        self.length = length
        self.cipher_len = self.length + self.sec_len

        # Calculate the number of helper values needed to be able to reproduce
        # keys given ham_err and rep_err. See "Reusable Fuzzy Extractors for
        # Low-Entropy Distributions" by Canetti, et al. for details.
        bits = length * 8
        const = float(ham_err) / log(bits)
        num_helpers = (bits ** const) * log(float(2) / rep_err, 2)

        # num_helpers needs to be an integer
        self.num_helpers = int(round(num_helpers))

    def parse_locker_args(self, hash_func='sha256', sec_len=2, nonce_len=16):
        """Parse arguments for digital lockers

        :param hash_func: The hash function to use for the digital locker (default: sha256).
        :param sec_len: security parameter. This is used to determine if the locker
            is unlocked successfully with accuracy (1 - 2 ^ -sec_len).
        :param nonce_len: Length in bytes of nonce (salt) used in digital locker (default: 16).
        """
        self.hash_func = hash_func
        self.sec_len = sec_len
        self.nonce_len = nonce_len

    def generate(self, value):
        """Takes a source value and produces a key and public helper

        This method should be used once at enrollment.

        Note that the "public helper" is actually a tuple. This whole tuple should be
        passed as the helpers argument to reproduce().

        :param value: the value to generate a key and public helper for.
        :rtype: (key, helper)
        """
        if isinstance(value, (bytes, str)):
            value = np.fromstring(value, dtype=np.uint8)

        key = np.fromstring(urandom(self.length), dtype=np.uint8)
        key_pad = np.concatenate((key, np.zeros(self.sec_len, dtype=np.uint8)))

        nonces = np.zeros((self.num_helpers, self.nonce_len), dtype=np.uint8)
        masks = np.zeros((self.num_helpers, self.length), dtype=np.uint8)
        digests = np.zeros((self.num_helpers, self.cipher_len), dtype=np.uint8)

        for helper in range(self.num_helpers):
            nonces[helper] = np.fromstring(urandom(self.nonce_len), dtype=np.uint8)
            masks[helper] = np.fromstring(urandom(self.length), dtype=np.uint8)

        # By masking the value with random masks, we adjust the probability that given
        # another noisy reading of the same source, enough bits will match for the new
        # reading & mask to equal the old reading & mask.

        vectors = np.bitwise_and(masks, value)

        # The "digital locker" is a simple crypto primitive made by hashing a "key"
        # xor a "value". The only efficient way to get the value back is to know
        # the key, which can then be hashed again xor the ciphertext. This is referred
        # to as locking and unlocking the digital locker, respectively.

        for helper in range(self.num_helpers):
            d_vector = vectors[helper].tobytes()
            d_nonce = nonces[helper].tobytes()
            digest = pbkdf2_hmac(self.hash_func, d_vector, d_nonce, 1, self.cipher_len)
            digests[helper] = np.fromstring(digest, dtype=np.uint8)

        ciphers = np.bitwise_xor(digests, key_pad)

        return (key.tobytes(), (ciphers, masks, nonces))

    def reproduce(self, value, helpers):
        """Takes a source value and a public helper and produces a key

        Given a helper value that matches and a source value that is close to
        those produced by generate, the same key will be produced.

        :param value: the value to reproduce a key for.
        :param helpers: the previously generated public helper.
        :rtype: key or None
        """
        if isinstance(value, (bytes, str)):
            value = np.fromstring(value, dtype=np.uint8)

        if self.length != len(value):
            raise ValueError('Cannot reproduce key for value of different length')

        ciphers = helpers[0]
        masks = helpers[1]
        nonces = helpers[2]

        vectors = np.bitwise_and(masks, value)

        digests = np.zeros((self.num_helpers, self.cipher_len), dtype=np.uint8)
        for helper in range(self.num_helpers):
            d_vector = vectors[helper].tobytes()
            d_nonce = nonces[helper].tobytes()
            digest = pbkdf2_hmac(self.hash_func, d_vector, d_nonce, 1, self.cipher_len)
            digests[helper] = np.fromstring(digest, dtype=np.uint8)

        plains = np.bitwise_xor(digests, ciphers)

        # When the key was stored in the digital lockers, extra null bytes were added
        # onto the end, which makes it each to detect if we've successfully unlocked
        # the locker.

        checks = np.sum(plains[:, -self.sec_len:], axis=1)
        for check in range(self.num_helpers):
            if checks[check] == 0:
                return plains[check, :-self.sec_len].tobytes()

        return None
