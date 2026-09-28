# ASN / IP / Domain Geolocation

Module: `geo_osint/correlation/{asn,ip,domain}_geolocation.py` (spec §12–14).

Each engine turns a network identifier into evidence-backed
`GeoObservation`s and carries **explicit, honest limitations** on what a geo signal
actually proves.

## IP geolocation (§13)

`IPGeolocationEngine`:

* **Public IPs only** — private/loopback/link-local/reserved addresses are refused
  (reuses `osint.utils.validators.is_public_ip`), so the engine can never probe
  internal networks.
* **Never an exact physical location** — every observation records provider
  precision (city-level at best, often country-level) and the standing limitation
  that IP geolocation is an ISP/registry *estimate*, not a device fix.
* Provider is pluggable (default `ipwho.is`, no key); `parse_ipwhois` is a pure,
  offline-tested parser; the network call degrades gracefully.

## ASN geolocation (§12)

`ASNGeolocationEngine` reuses the repository's `osint.sources.bgpview` source (the
global BGP table — public infrastructure metadata) to map an ASN to its registered
holder, country and RIR. The observation's coordinate, when set, is the **country
centroid** (clearly marked as a country-level approximation), never a claim about
where the AS's routers physically sit. Limitation: registration/routing data locates
an organisation's *registration*, not its equipment (spec §12 "do not infer exact
infrastructure ownership").

## Domain geolocation (§14)

`DomainGeolocationEngine` gathers weak, independent signals and explains each:

| Signal | Confidence | Meaning |
|--------|-----------:|---------|
| ccTLD (offline) | 0.15–0.35 | registry association, not hosting/location; generic ccTLDs (`.io`, `.co`, `.tv`, …) are discounted |
| RDAP registrant country (online) | 0.40 | registrant declaration; may be a privacy service or registrar |
| hosting IP (online) | provider | A/AAAA record geolocated via the IP engine — CDN/host edge, often not the operator |

Signals are combined by the correlation layer with noisy-OR **only where genuinely
independent**.

## Example

```python
import asyncio
from geo_osint.correlation import DomainGeolocationEngine
d = DomainGeolocationEngine()
print(d.signals_offline("bank.co.th").countries)   # ['TH'] (ccTLD, low confidence)
```
