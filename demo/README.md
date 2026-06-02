# Archer demo

A throwaway, self-contained instance for showing Archer off without a
sensor fleet or real capture.

```sh
./demo.sh
```

From the repo root this builds the binary, seeds a temporary data
directory from the sample Zeek logs in `demo/logs/`, registers a demo
admin, runs one analysis pass, and serves the workbench at
`https://localhost:18443` until you press Ctrl-C. Everything lives in a
temp directory that is wiped on exit — no production deployment is
touched.

Default login is `demo@archer.local` / `archerdemo`. Override the port
or credentials with `ARCHER_DEMO_PORT`, `ARCHER_DEMO_EMAIL`, and
`ARCHER_DEMO_PASSWORD`.

## Sample logs

`demo/logs/<scenario>/<date>/<zeek>.log` holds one curated scenario per
directory, covering the detector families: beaconing (steady, jittered,
scrambled, slow, multimode, URL, DNS), strobe, long connection, exfil,
lateral movement, off-hours, DNS tunneling / NXDOMAIN / subdomain
diversity / suspicious TLD / DoH bypass, HTTP C2 URIs and domain
fronting, suspicious user-agents and files, malicious JA3/JA4, weak TLS,
no-SNI, x509 anomalies, suspicious files/MIME, and Zeek weird/notice
passthrough.

The logs are derived from the detector fixtures under
`internal/analysis/testdata/zeek/`, wrapped in a Zeek date tree so they
ingest like a real sensor push. The TI-feed scenarios are omitted here
because they need external feeds loaded to match.
