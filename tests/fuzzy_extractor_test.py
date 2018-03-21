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

"""Test cases for FuzzyExtractor class"""

import random
import sys
import string
from fuzzy_extractor import FuzzyExtractor

def test_init():
    """Test initialization to make sure it produces sane values"""
    random.seed()

    lens = [random.randint(1, 32) for _ in range(10000)]
    ham_errs = [random.randint(1, 7) for _ in range(len(lens))]

    for b_len, ham_err in zip(lens, ham_errs):
        extractor = FuzzyExtractor(b_len, ham_err)
        sys.stdout.write(str(b_len) + ' ' + str(ham_err) + "\n")
        assert extractor.num_helpers >= 1

def test_reproduce():
    """Tests that a fuzzy extractor can reproduce the same key from the same input"""
    random.seed()

    val_len = 30
    chars = string.ascii_letters
    values = list()
    for _ in range(150):
        values.append("".join(random.choice(chars) for _ in range(val_len)))

    for value in values:
        extractor = FuzzyExtractor(val_len, 2)
        key, helpers = extractor.generate(value)
        assert extractor.reproduce(value, helpers) == key

def test_reproduce_fuzzy():
    """Test fuzzy extractor reproduce with some noise added in"""
    random.seed()

    val_len = 30
    chars = string.ascii_letters
    values = list()
    for _ in range(5):
        values.append("".join(random.choice(chars) for _ in range(val_len)))

    for value in values:
        # extractor can handle at least 8 bit flips
        extractor = FuzzyExtractor(val_len, 8)
        key, helpers = extractor.generate(value)
        # change a random character, which could flip up to 8 bits
        pos = random.randint(0, val_len - 2)
        value_noisy = value[:pos] + random.choice(chars) + value[pos + 1:]
        # extractor should still produce same key
        assert extractor.reproduce(value_noisy, helpers) == key

def test_reproduce_bad():
    """Test fuzzy extractor produces different key when new value is too different"""
    value_orig = 'AABBCCDD'
    value_good = 'ABBBCCDD'  #  2 bits flipped
    value_bad = 'A0B00CDD'   # 13 bits flipped

    extractor = FuzzyExtractor(8, 2)
    key, helpers = extractor.generate(value_orig)

    assert extractor.reproduce(value_good, helpers) == key
    assert extractor.reproduce(value_bad, helpers) != key

def test_encoding():
    """Test ability to encode and decode non-ASCII characters"""
    value = b'\xFF' * 15

    extractor = FuzzyExtractor(len(value), 2)
    key, helpers = extractor.generate(value)

    assert extractor.reproduce(value, helpers) == key

def test_locker_args():
    """Test that locker args passed to FuzzyExtractor work"""
    val = b'AAAABBBBCCCCDDDD'

    extractor = FuzzyExtractor(len(val), 1, hash_func='sha512', sec_len=3, nonce_len=32)
    key, helpers = extractor.generate(val)

    assert extractor.reproduce(val, helpers) == key
