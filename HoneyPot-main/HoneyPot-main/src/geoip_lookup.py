"""Thin wrapper around MaxMind GeoLite2 city + ASN databases.

Degrades gracefully to "unknown" fields when the .mmdb files aren't
present, so the honeypot is fully functional without a MaxMind account.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:  # pragma: no cover
    _GEOIP2_AVAILABLE = False

logger = logging.getLogger("honeypot")

UNKNOWN = "unknown"


@dataclass
class GeoInfo:
    country: str = UNKNOWN
    city: str = UNKNOWN
    asn: str = UNKNOWN
    isp: str = UNKNOWN
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class GeoIPResolver:
    def __init__(self, city_db_path: str, asn_db_path: str, enabled: bool = True):
        self.enabled = enabled and _GEOIP2_AVAILABLE
        self._city_reader = None
        self._asn_reader = None

        if not self.enabled:
            if enabled and not _GEOIP2_AVAILABLE:
                logger.warning("geoip2 package not installed; GeoIP lookups disabled.")
            return

        try:
            self._city_reader = geoip2.database.Reader(city_db_path)
        except Exception as exc:
            logger.warning("Could not open GeoLite2 City DB (%s): %s", city_db_path, exc)

        try:
            self._asn_reader = geoip2.database.Reader(asn_db_path)
        except Exception as exc:
            logger.warning("Could not open GeoLite2 ASN DB (%s): %s", asn_db_path, exc)

    def lookup(self, ip: str) -> GeoInfo:
        info = GeoInfo()
        if not self.enabled:
            return info

        if self._city_reader is not None:
            try:
                resp = self._city_reader.city(ip)
                info.country = resp.country.name or UNKNOWN
                info.city = resp.city.name or UNKNOWN
                info.latitude = resp.location.latitude
                info.longitude = resp.location.longitude
            except Exception:
                pass  # private/reserved IPs, DB miss, etc.

        if self._asn_reader is not None:
            try:
                resp = self._asn_reader.asn(ip)
                info.asn = f"AS{resp.autonomous_system_number}"
                info.isp = resp.autonomous_system_organization or UNKNOWN
            except Exception:
                pass

        return info

    def close(self):
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
