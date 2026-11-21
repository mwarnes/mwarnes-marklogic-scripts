#!/usr/bin/env python3
"""Clone a MarkLogic app server to a new port, or remove a clone made by this script.

Run with no arguments (or -h / --help) for full usage.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import json
import os
import ssl
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

TOOL = "appserver-clone"
FORMAT_VERSION = 1

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_PREFLIGHT = 2
EXIT_API = 3
EXIT_DECLINED = 4

# Properties the Management API returns on GET but rejects on POST /manage/v2/servers.
# Keep this empty unless a live test proves otherwise, and give every entry a comment saying why.
STRIP_ON_POST: tuple = ()


class CloneError(Exception):
    """An expected failure: printed as 'error: ...' (plus an optional hint) and mapped to an exit code."""

    def __init__(self, message: str, exit_code: int, hint: str | None = None):
        super().__init__(message)
        self.exit_code = exit_code
        self.hint = hint


class ApiError(CloneError):
    """The Management API answered with an error status."""

    def __init__(self, method: str, path: str, status: int, message_code: str = "", message: str = ""):
        self.method = method
        self.path = path
        self.status = status
        self.message_code = message_code
        text = f"{method} {path} → {status}"
        if message_code:
            text += f" {message_code}"
        if message:
            text += f": {message}"
        super().__init__(text, EXIT_API)


class TransportError(CloneError):
    """The Management API could not be reached."""

    def __init__(self, message: str):
        super().__init__(message, EXIT_API, hint="check MARKLOGIC_HOST, MARKLOGIC_MANAGE_PORT and MARKLOGIC_SCHEME")


@dataclass(frozen=True)
class Config:
    host: str
    user: str
    password: str = field(repr=False)
    port: int = 8002
    scheme: str = "http"
    insecure: bool = False
    ssl_context: ssl.SSLContext | None = field(default=None, repr=False, compare=False)

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def load_config(environ) -> Config:
    """Build the connection settings from environment variables only."""
    missing = [v for v in ("MARKLOGIC_HOST", "MARKLOGIC_USER", "MARKLOGIC_PASS") if not environ.get(v)]
    if missing:
        raise CloneError("missing environment variable(s): " + ", ".join(missing), EXIT_USAGE,
                         hint="connection settings are read only from the environment; see --help")
    scheme = environ.get("MARKLOGIC_SCHEME", "http").strip().lower()
    if scheme not in ("http", "https"):
        raise CloneError(f"MARKLOGIC_SCHEME must be http or https, not '{scheme}'", EXIT_USAGE)
    raw_port = environ.get("MARKLOGIC_MANAGE_PORT", "8002").strip()
    if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        raise CloneError(f"MARKLOGIC_MANAGE_PORT must be a port number (1-65535), not '{raw_port}'", EXIT_USAGE)
    insecure = environ.get("MARKLOGIC_INSECURE", "") == "1"
    context = None
    if scheme == "https":
        if insecure:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            cafile = environ.get("MARKLOGIC_CA_CERT") or None
            try:
                context = ssl.create_default_context(cafile=cafile)
            except (OSError, ssl.SSLError) as e:
                raise CloneError(f"cannot load MARKLOGIC_CA_CERT '{cafile}': {e}", EXIT_USAGE) from None
    return Config(host=environ["MARKLOGIC_HOST"].strip(), user=environ["MARKLOGIC_USER"],
                  password=environ["MARKLOGIC_PASS"], port=int(raw_port), scheme=scheme,
                  insecure=insecure, ssl_context=context)


def server_path(name: str, suffix: str = "") -> str:
    return "/manage/v2/servers/" + urllib.parse.quote(name, safe="") + suffix


def api_error(method: str, path: str, status: int, raw: bytes) -> ApiError:
    """Turn an error response (MarkLogic errorResponse JSON, or anything else) into an ApiError."""
    code = message = ""
    try:
        detail = json.loads(raw.decode("utf-8", "replace")).get("errorResponse", {})
        code = detail.get("messageCode", "") or ""
        message = detail.get("message", "") or ""
    except (ValueError, AttributeError):
        pass
    if code and message.startswith(code + ":"):
        message = message[len(code) + 1:].strip()
    err = ApiError(method, path, status, code, message)
    if status == 401:
        err.hint = "check MARKLOGIC_USER and MARKLOGIC_PASS"
    elif status == 403:
        err.hint = "MARKLOGIC_USER needs the manage-admin or admin role"
    return err


class ManageClient:
    """Minimal Management API client: digest auth, JSON in and out."""

    def __init__(self, config: Config, opener=None, timeout: float = 30):
        self.base_url = config.base_url
        self.timeout = timeout
        if opener is None:
            passwords = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            passwords.add_password(None, self.base_url, config.user, config.password)
            handlers = [urllib.request.HTTPDigestAuthHandler(passwords)]
            if config.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=config.ssl_context))
            opener = urllib.request.build_opener(*handlers)
        self._opener = opener

    def _request(self, method: str, path: str, params=None, body=None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as e:
            raise api_error(method, path, e.code, e.read()) from None
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise TransportError(f"{method} {path}: cannot reach {self.base_url}: {reason}") from None

    @staticmethod
    def _json_or_none(raw: bytes):
        if not raw or not raw.strip():
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return None

    def get_json(self, path: str, params=None) -> dict:
        status, raw = self._request("GET", path, params)
        data = self._json_or_none(raw)
        if not isinstance(data, dict):
            raise ApiError("GET", path, status, message="response was not a JSON object")
        return data

    def post_json(self, path: str, params, body: dict):
        status, raw = self._request("POST", path, params, body)
        return status, self._json_or_none(raw)

    def delete(self, path: str, params):
        status, raw = self._request("DELETE", path, params)
        return status, self._json_or_none(raw)
