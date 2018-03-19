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

"""Test cases for DigitalLocker class"""

import random
import string
import pytest
from fuzzy_extractor import DigitalLocker

def test_locker():
    """Tests that values can be locked and unlocked with only the correct key"""
    random.seed()

    chars = string.ascii_letters
    values = list()
    keys = list()
    for _ in range(150):
        values.append(bytearray("".join(random.choice(chars) for _ in range(30)), 'utf8'))
        keys.append(bytearray("".join(random.choice(chars) for _ in range(32)), 'utf8'))

    for value, key in zip(values, keys):
        locker = DigitalLocker()
        locker.lock(key, value)
        assert value == locker.unlock(key)
        assert locker.unlock(key[:-1]) is None

def test_lock_exception():
    """Digital lockers should not allow values that are longer than the hash length"""
    key = bytearray('AABBCCDD', 'utf8')
    value = bytearray('AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP', 'utf8')  # This is too long for sha256
    locker = DigitalLocker()
    with pytest.raises(ValueError):
        locker.lock(key, value)

def test_unlock_exception():
    """Digital lockers should not allow unlocking before a value has been locked into them"""
    locker = DigitalLocker()
    with pytest.raises(Exception):
        locker.unlock('AABBCCDD')
