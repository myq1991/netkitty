# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Schema-driven encode/decode of 188 protocol headers — from Ethernet/IP/TCP/UDP
  and the mainstream application layer through a deep bench of industrial/OT
  protocols (Modbus, DNP3, IEC 104, IEC 61850 GOOSE/SV/MMS, S7comm, OPC UA,
  PROFINET, EtherCAT, EtherNet/IP, BACnet and more).
- One executable JSON Schema per header doubles as field tree, byte codec, Ajv
  validator and UI form metadata. Decode never throws; errors accumulate on a
  field-path-addressed list.
