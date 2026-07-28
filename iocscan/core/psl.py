"""Single snapshot-only PSL extractor, shared process-wide.

Empty `suffix_list_urls` + `cache_dir=None` mean this never fetches or caches
at runtime — only the suffix-list snapshot bundled in the tldextract package.
Building the suffix trie costs ~13 ms / ~6 MB once per process on first call,
so consumers share this one instance instead of paying that per module.
Private-PSL interpretation (github.io, blogspot.com counting as suffixes) is
a per-call flag, not a second instance:

    EXTRACT(host, include_psl_private_domains=True)
"""
from __future__ import annotations

import tldextract

EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
