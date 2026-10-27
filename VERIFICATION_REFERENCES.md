# Implementation references and scope

Public primary documentation consulted while preparing the fix:
- PKWARE APPNOTE 6.3.10 (2022-11-01), sections 4.3.7–4.3.16 and 4.4: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT . Referenced only; not redistributed.
- Python 3.13 zlib documentation, `decompressobj`, `max_length`, `eof`, `unconsumed_tail`, `unused_data`: https://docs.python.org/3.13/library/zlib.html . Raw DEFLATE is bounded and the entire member must terminate.
- Python 3.13 JSON documentation, `parse_int` and integer conversion limit: https://docs.python.org/3.13/library/json.html . Own fixed lexical budget prevents process-setting-dependent acceptance.

Local test interpreter is identified in the external execution receipt, not inferred from online documentation. The implemented ZIP profile is deliberately stricter than general ZIP. CRC validation is transport consistency, not cryptographic authenticity. No external documentation is a proof of correctness of this implementation.
