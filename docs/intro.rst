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
