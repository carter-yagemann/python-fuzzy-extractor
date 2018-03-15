Fuzzy Extractor
===============

A Python implementation of fuzzy extractor.

Introduction
============

Fuzzy extractors are a cryptography primitive designed to reliably derive keys
from noisy sources. This makes them suitable for areas like biometric
authentication where two measurements of the same subject can yield slightly
different values. This implementation uses hamming distance as its error
metric, meaning that two binary strings will produce the same key with very
high probability if their hamming distance is within some given threshold.

The storage and retrieval of keys is performed using a primitive known as a
*digital locker*. More information is available in the references section of
this documentation.

Note that this is a probabilistic primitive based on very recent research. Use
this library in real security applications at your own risk, ideally after
performing some empirical evaluation for your chosen thresholds.

Installing
==========

This library can be install from pip::

    $ pip install fuzzy-extractor

Development
-----------

This repository comes with a `Makefile` to help with getting a development
environment configured::

    $ make help

Usage
=====

Getting Started
---------------

This section will cover the basics of using fuzzy extractors. First, we need
to create an extractor::

    from fuzzy_extractor import FuzzyExtractor
    
    extractor = FuzzyExtractor(16, 8)

The extractor we just created will accept 16 byte (128-bit) input values and
guarantees that inputs within 8 bits of each other will produce the same key
with over 0.9999 probability (see the references for more details).

We're now ready to generate a key for some input::

    key, helper = extractor.generate('AABBCCDDEEFFGGHH')

Note that `generate()` returned two things: `key` and `helper`. The former is
the secret that can now be used for further cryptography. The latter does not
need to be protected (i.e., it is not a secret), but it does need to be stored
somewhere if we want to be able to reproduce the same key later.

As long as we have the public helper, we can reproduce the key with any input
close enough to the original::

    r_key = extractor.reproduce('AABBCCDDEEFFGGHH', helper)  # r_key should equal key
    r_key = extractor.reproduce('AABBCCDDEEFFGGHI', helper)  # r_key will probably still equal key!
    r_key = extractor.reproduce('AAAAAAAAAAAAAAAA', helper)  # r_key is no longer likely to equal key

Documentation
-------------

See the `doc` directory for documentation.

References
==========

- Canetti, Ran, et al. "Reusable fuzzy extractors for low-entropy distributions." *Annual International Conference on the Theory and Applications of Cryptographic Techniques*. Springer, Berlin, Heidelberg, 2016.
