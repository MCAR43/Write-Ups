#!/usr/bin/env python
import base64, codecs, sys
encr = ['=RFn0AKnlMHMPIzpyuTI0ITG', 'mVGZ3O3omkJLmy2pcuTq']
for enc in encr:
	enc = enc[::-1]
	print enc
	enc = codecs.decode(enc, 'rot13')
	print enc
	enc = base64.b64decode(enc)
	print enc
