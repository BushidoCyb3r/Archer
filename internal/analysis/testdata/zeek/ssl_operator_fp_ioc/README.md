# ssl_operator_fp_ioc

Exercises the operator JA3/JA4 fingerprint IOC list. Neither fingerprint in
`ssl.log` is in the built-in `KnownBadJA3`/`KnownBadJA4` tables — they only
flag because `operator_fingerprints.json` adds them to the operator list
(injected via `Analyzer.SetOperatorFingerprints`). The expected output carries
`Malicious JA3` and `Malicious JA4` findings identical in shape to a built-in
match, with the `Operator IOC` label in the detail string.
