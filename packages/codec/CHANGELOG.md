# Changelog

All notable changes to `@netkitty/codec` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this package uses
independent [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **China smart-substation stack (DL/T 2811-2024 CMS + IEC 61850 MMS).** A full
  `TPKT → COTP → ISO-Session → Presentation → MMS` stack, plus the State-Grid CMS framing
  over TCP `8102`/`9102`.
  - A from-scratch, never-throwing **ASN.1 ALIGNED BASIC-PER decoder** (`PerReader` + `PerDecoder`)
    driving CMS service data for display: `AssociateNegotiate` (SC 154, both directions),
    `GetAllDataDefinition` (SC 155) request, `GetAllDataValues` (SC 83) request, and `Associate`
    (SC 1) request. Exact 64-bit integers (via `BigInt`), and X.691 small-string / small-BIT-STRING
    handling.
  - The MMS layer surfaces the confirmed service, invoke id and the object/variable names referenced.
  - The ISO-Session layer surfaces the connection-phase ACSE (AARQ/AARE type, application-context OID,
    AP-titles) and the negotiated MMS-initiate parameters.
  - CMS data/definition responses use the GB/T 33603 "M-coding", whose exact name/length framing is not
    fully specified in the available standards, so those bodies are kept verbatim and their readable
    IEC 61850 identifiers are surfaced best-effort.
- **Large protocol expansion.** The built-in header set grew to **188 protocols**, adding broad
  application, routing, tunnelling, VoIP, database, messaging and industrial/OT coverage
  (Modbus TCP/UDP, DNP3, S7comm, EtherNet/IP, PROFINET, EtherCAT, BACnet/IP, C37.118, OPC UA,
  HART-IP, KNXnet/IP, IEC 61850-90-5 R-GOOSE, and many more). See the README's built-in headers table.
- **LLC/SNAP 802.3 substrate** (STP, CDP, IS-IS) and **COTP payload sub-layering** (RDP, S7comm),
  and a decode-as-only WebSocket frame codec.

### Changed

- **Flattened the package source layout.** Now that `codec` is its own package, the
  `src/lib/codec/…` nesting (a leftover from the pre-monorepo single-package layout) was flattened to
  match the sibling packages: the codec engine lives directly under `src/` (`abstracts/`, `headers/`,
  `types/`, `Codec.ts`, `PacketHeaders.ts`), shared utilities under `src/lib/`, and `helper/` + `schema/`
  under `src/`. No public API or on-the-wire behaviour changed; byte-perfect round-trip is unchanged.

### Removed

- Dev-only batch-integration scripts (`scripts/register-headers.js`, `scripts/integrate.sh`) that were
  not part of the build or runtime.
