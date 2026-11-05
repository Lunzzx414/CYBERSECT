import ipaddress
import logging
import math
from functools import lru_cache
from pathlib import Path
from typing import Any

import geoip2.database
import httpx
from geoip2.errors import AddressNotFoundError
from maxminddb.errors import InvalidDatabaseError

from app.config import settings


LOGGER = logging.getLogger(__name__)
IPWHOIS_FIELDS = (
    "success,message,country,country_code,continent,continent_code,"
    "city,latitude,longitude"
)


def _empty_location(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "country": None,
        "country_code": None,
        "continent": None,
        "continent_code": None,
        "city": None,
        "latitude": None,
        "longitude": None,
    }


@lru_cache(maxsize=1)
def _reader(database_path: str) -> geoip2.database.Reader:
    return geoip2.database.Reader(database_path)


def _validate_city_database(reader: geoip2.database.Reader) -> None:
    database_type = reader.metadata().database_type
    if "city" not in database_type.lower():
        raise ValueError("The configured MaxMind database is not a City database.")


@lru_cache(maxsize=4096)
def _lookup_cached(database_path: str, address: str) -> dict[str, Any]:
    try:
        reader = _reader(database_path)
        _validate_city_database(reader)
        result = reader.city(address)
    except AddressNotFoundError:
        return _empty_location("not_found")

    location = result.location
    return {
        "status": "located",
        "country": result.country.names.get("en"),
        "country_code": result.country.iso_code,
        "continent": result.continent.names.get("en"),
        "continent_code": result.continent.code,
        "city": result.city.names.get("en"),
        "latitude": location.latitude,
        "longitude": location.longitude,
    }


@lru_cache(maxsize=4096)
def _lookup_online_cached(address: str) -> dict[str, Any]:
    try:
        response = httpx.get(
            f"https://ipwho.is/{address}",
            params={"fields": IPWHOIS_FIELDS},
            timeout=5.0,
        )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict) or result.get("success") is not True:
            message = result.get("message", "The provider could not locate this IP.") if isinstance(result, dict) else "Invalid response from the provider."
            LOGGER.warning("Online IP geolocation lookup failed: %s", message)
            return _empty_location("unavailable")

        latitude = result.get("latitude")
        longitude = result.get("longitude")
        country = result.get("country")
        if (
            not isinstance(country, str)
            or not country
            or not isinstance(latitude, (int, float))
            or isinstance(latitude, bool)
            or not isinstance(longitude, (int, float))
            or isinstance(longitude, bool)
            or not math.isfinite(latitude)
            or not math.isfinite(longitude)
            or not -90 <= latitude <= 90
            or not -180 <= longitude <= 180
        ):
            raise ValueError("The provider response is missing valid country coordinates.")

        return {
            "status": "located",
            "country": country,
            "country_code": result.get("country_code"),
            "continent": result.get("continent"),
            "continent_code": result.get("continent_code"),
            "city": result.get("city"),
            "latitude": latitude,
            "longitude": longitude,
        }
    except (httpx.HTTPError, ValueError) as error:
        LOGGER.warning("Online IP geolocation lookup failed: %s", error)
        return _empty_location("unavailable")


def geolocation_status() -> dict[str, str]:
    if settings.GEOLOCATION_PROVIDER == "ipwhois":
        return {
            "status": "ready",
            "message": "Online HTTPS lookup via ipwho.is is active; public source IPs are sent to this provider for approximate geolocation.",
        }

    database_path = settings.GEOLITE2_CITY_DB_PATH
    if database_path is None:
        return {
            "status": "not_configured",
            "message": "Set AIR_DS_GEOLITE2_CITY_DB_PATH to a licensed GeoLite2 City .mmdb file.",
        }
    if not database_path.is_file():
        return {
            "status": "unavailable",
            "message": "The configured GeoLite2 City database file was not found.",
        }
    try:
        _validate_city_database(_reader(str(database_path)))
    except (InvalidDatabaseError, OSError, ValueError) as error:
        LOGGER.exception("Unable to open the configured GeoLite2 City database.")
        return {
            "status": "unavailable",
            "message": f"Unable to open GeoLite2 City database: {error}",
        }
    return {
        "status": "ready",
        "message": "Local GeoLite2 City database is active; source IPs are not sent to a third party.",
    }


def locate_ip(address: str) -> dict[str, Any]:
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        return _empty_location("invalid")

    if not parsed_address.is_global:
        return _empty_location("non_public")

    if settings.GEOLOCATION_PROVIDER == "ipwhois":
        return _lookup_online_cached(str(parsed_address))

    database_path: Path | None = settings.GEOLITE2_CITY_DB_PATH
    if database_path is None or not database_path.is_file():
        return _empty_location("unavailable")

    try:
        return _lookup_cached(str(database_path), str(parsed_address))
    except (InvalidDatabaseError, OSError, ValueError) as error:
        LOGGER.exception("GeoIP lookup failed.")
        return _empty_location("unavailable")


def enrich_attack_geolocation(attacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = []
    for attack in attacks:
        event = dict(attack)
        event["location"] = locate_ip(str(event.get("client_ip", "")))
        enriched.append(event)
    return enriched
