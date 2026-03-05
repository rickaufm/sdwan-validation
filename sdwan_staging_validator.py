#!/usr/bin/env python3
"""
=============================================================================
Cisco Catalyst SD-WAN Staging Validation Script
=============================================================================
Author      : Ricardo (Cisco SE / SD-WAN SME)
Description : Validates the staging/ZTP provisioning process for SD-WAN
              WAN Edge routers by querying the SD-WAN Manager REST API.
              Supports two device selection modes:
                • CSV mode  (--csv devices.csv) — explicit device list from file
                • Manager mode (no --csv)       — dynamic device list from Manager,
                  controlled by SCOPE config variable:
                    "all"     → validate every registered WAN Edge device
                    "staging" → validate only devices carrying the STAGING_TAG tag

Checks performed per device:
  1. Configuration-Group deployment status
  2. Device reachability
  3. Number of control connections
  4. Number of BFD sessions (tunnels)
  5. Number of TLOCs
  6. Device health state
  7. Software version

Usage:
  python sdwan_staging_validator.py --csv devices.csv   # CSV mode
  python sdwan_staging_validator.py                       # Manager mode (SCOPE="all" or "staging")

CSV format (header row required):
  hostname,serial_number,system_ip

Authentication:
  Auto-detects the best available method for the connected Manager version:
    • JWT-based login  (POST /dataservice/client/login)   — Manager ≥ 20.12
      JWT Bearer token + CSRF token applied to all requests.
    • Session-based fallback  (POST /j_security_check + GET /dataservice/client/token)
      Used automatically when the JWT endpoint returns an HTML login page,
      indicating an older Manager release (≤ 20.11).
  The method used is printed at runtime so the operator always knows which
  authentication path was taken.

Dependencies:
  pip install requests urllib3 jinja2
=============================================================================
"""

import argparse
import csv
import sys
import urllib3
from datetime import datetime
from pathlib import Path

import requests
from jinja2 import Template

# =============================================================================
# >>>  CONFIGURATION — edit these variables before running  <<<
# =============================================================================

VMANAGE_HOST     = "192.168.1.1"       # SD-WAN Manager IP or hostname
VMANAGE_PORT     = 443                 # SD-WAN Manager HTTPS port (usually 443 or 8443)
VMANAGE_USERNAME = "admin"             # SD-WAN Manager username
VMANAGE_PASSWORD = "admin"             # SD-WAN Manager password

# Set to True to ignore untrusted/self-signed TLS certificates (lab/staging use)
DISABLE_SSL_VERIFY = True

# Minimum expected values for staging validation (adjust per your design)
MIN_CONTROL_CONNECTIONS = 2            # Minimum vSmart/Controller connections expected
MIN_BFD_SESSIONS_UP     = 1            # Minimum BFD sessions expected to be UP
MIN_OMP_PEERS           = 2            # Minimum OMP peers expected to be UP
MIN_TLOCS               = 1            # Minimum TLOCs expected
ENFORCE_REACHABILITY    = True         # True = skip all checks and mark FAIL if device is unreachable; False = run all checks regardless
EXPECTED_TLOC_COLORS    = None         # Optional list of required TLOC colors, e.g. ["lte", "private1"]. None = skip check
EXPECTED_SW_VERSION     = None         # Set e.g. "17.12.1a" to enforce, or None to skip check
CHECK_CELLULAR          = False        # True = add Cellular Status check (interface, APN, IP, RAT); False = skip

# ── Manager-driven device scope (used only when --csv is NOT provided) ──────
SCOPE       = "staging"   # "all"     → validate every registered WAN Edge device
                          # "staging" → validate only devices with the STAGING_TAG tag
STAGING_TAG = "staging"   # Tag name to filter on when SCOPE = "staging"

# Output HTML report filename
OUTPUT_HTML = "sdwan_staging_report.html"

# =============================================================================
# Suppress SSL warnings when DISABLE_SSL_VERIFY = True
# =============================================================================
if DISABLE_SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# SD-WAN Manager API Client
# =============================================================================

class SDWANManagerClient:
    """Handles authentication and API calls to Cisco Catalyst SD-WAN Manager."""

    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool):
        self.base_url     = f"https://{host}:{port}"
        self.username     = username
        self.password     = password
        self.verify_ssl   = verify_ssl
        self.session      = requests.Session()
        self.session.verify = verify_ssl
        self._jwt_token   = None   # Set when JWT auth succeeds
        self._auth_method = None   # "jwt" or "session" — recorded after login

    # -------------------------------------------------------------------------
    # Authentication  —  auto-detect JWT (≥ 20.12) with session fallback
    # -------------------------------------------------------------------------

    def login(self) -> None:
        """
        Authenticate to SD-WAN Manager using the best available method.

        Strategy
        --------
        1. Try JWT-based login  (POST /dataservice/client/login)
           Available on SD-WAN Manager 20.12 and later.
           On success: Bearer token + CSRF token applied to the session.

        2. If the Manager returns an HTML login page (older release that does
           not support the JWT endpoint), automatically fall back to the
           classic session-based login:
             a. POST /j_security_check  →  JSESSIONID cookie
             b. GET  /dataservice/client/token  →  XSRF token

        The method that succeeded is stored in self._auth_method ("jwt" or
        "session") and printed so the operator always knows which path was used.
        """
        print(f"[*] Authenticating to SD-WAN Manager at {self.base_url} ...")

        if self._try_jwt_login():
            self._auth_method = "jwt"
            print("[+] Authentication successful  (method: JWT / Bearer token)")
        else:
            print("    JWT endpoint not available on this Manager version — "
                  "falling back to session-based authentication ...")
            self._try_session_login()
            self._auth_method = "session"
            print("[+] Authentication successful  (method: session cookie + XSRF token)")

    # ── JWT login  (Manager ≥ 20.12) ─────────────────────────────────────────

    def _try_jwt_login(self) -> bool:
        """
        Attempt JWT login via POST /dataservice/client/login.

        Returns True on success, False when the endpoint does not exist on
        this Manager version (detected by an HTML response body).
        Raises RuntimeError for genuine credential / permission failures.
        """
        login_url  = f"{self.base_url}/dataservice/client/login"
        login_body = {"username": self.username, "password": self.password}

        resp = self.session.post(
            login_url,
            json    = login_body,
            headers = {"Content-Type": "application/json"},
            timeout = 30,
        )

        # A hard credential failure — do not fall back, raise immediately
        if resp.status_code == 401:
            raise RuntimeError(
                "Authentication failed (HTTP 401) — wrong username or password."
            )
        if resp.status_code == 403:
            raise RuntimeError(
                "Authentication failed (HTTP 403) — account may be locked "
                "or lacks API access."
            )

        # If the Manager returned an HTML page the JWT endpoint does not exist
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" in content_type:
            return False   # signal caller to fall back to session auth

        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"JWT login failed (HTTP {resp.status_code}): {resp.text[:400]}"
            )

        # ── Parse JSON body safely ────────────────────────────────────
        payload  = {}
        raw_text = resp.text.strip()
        if raw_text:
            try:
                payload = resp.json()
            except ValueError:
                # Non-HTML, non-JSON — unexpected; treat as unsupported
                return False

        # ── Extract JWT access token ──────────────────────────────────
        # Search: JSON body → Authorization header → cookie
        jwt = None
        if isinstance(payload, dict):
            jwt = (
                payload.get("token")
                or payload.get("access_token")
                or payload.get("jwtToken")
                or (payload.get("data") or {}).get("token")
            )
        elif isinstance(payload, str) and payload:
            jwt = payload

        if not jwt:
            auth_hdr = resp.headers.get("Authorization", "")
            if auth_hdr.lower().startswith("bearer "):
                jwt = auth_hdr.split(" ", 1)[1]

        if not jwt:
            for name in ("jwtToken", "jwt", "token", "AUTH_TOKEN"):
                jwt = resp.cookies.get(name)
                if jwt:
                    break

        if not jwt:
            # Got a 200 JSON response but no token field — likely unsupported
            return False

        # ── Extract CSRF token ────────────────────────────────────────
        # Search: JSON body → X-XSRF-TOKEN header
        csrf = None
        if isinstance(payload, dict):
            csrf = (
                payload.get("csrf")
                or payload.get("csrfToken")
                or payload.get("xsrfToken")
                or (payload.get("data") or {}).get("csrf")
            )
        if not csrf:
            csrf = resp.headers.get("X-XSRF-TOKEN")

        # ── Apply to session ──────────────────────────────────────────
        self._jwt_token = jwt
        self.session.headers.update({
            "Authorization" : f"Bearer {jwt}",
            "Content-Type"  : "application/json",
        })
        if csrf:
            self.session.headers.update({"X-XSRF-TOKEN": csrf})

        return True

    # ── Session-based login  (Manager ≤ 20.11) ───────────────────────────────

    def _try_session_login(self) -> None:
        """
        Classic two-step authentication:
          Step 1 — POST /j_security_check  → receives JSESSIONID cookie
          Step 2 — GET  /dataservice/client/token  → receives XSRF token
        Raises RuntimeError on failure.
        """
        # Step 1 — form POST
        login_url  = f"{self.base_url}/j_security_check"
        login_data = {"j_username": self.username, "j_password": self.password}

        resp = self.session.post(
            login_url,
            data    = login_data,
            headers = {"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects = True,
            timeout = 30,
        )

        # Bad credentials: Manager returns 200 but redirects back to login HTML
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" in content_type and "j_security_check" in resp.url:
            raise RuntimeError(
                "Session-based authentication failed — "
                "check username and password."
            )

        # Sanity-check that we got a JSESSIONID
        if not resp.cookies.get("JSESSIONID") and "JSESSIONID" not in str(resp.headers.get("set-cookie", "")):
            raise RuntimeError(
                f"Session-based authentication failed (HTTP {resp.status_code}) — "
                "no JSESSIONID received. Check credentials and Manager connectivity."
            )

        # Step 2 — retrieve XSRF token
        token_resp = self.session.get(
            f"{self.base_url}/dataservice/client/token",
            headers = {"Content-Type": "application/json"},
            timeout = 15,
        )
        if token_resp.status_code == 200:
            xsrf = token_resp.text.strip().strip('"')
            if xsrf:
                self.session.headers.update({"X-XSRF-TOKEN": xsrf})

        self.session.headers.update({"Content-Type": "application/json"})
        # Reuse _jwt_token flag as a generic "authenticated" sentinel
        self._jwt_token = "SESSION"

    # ─────────────────────────────────────────────────────────────────────────

    def logout(self) -> None:
        """
        Gracefully terminate the session on SD-WAN Manager.

        JWT sessions : POST /dataservice/client/logout
        Cookie sessions : GET /logout
        """
        try:
            if self._auth_method == "jwt":
                self.session.post(
                    f"{self.base_url}/dataservice/client/logout", timeout=10
                )
            else:
                self.session.get(
                    f"{self.base_url}/logout", timeout=10
                )
        except Exception:
            pass
        finally:
            self._jwt_token   = None
            self._auth_method = None
            self.session.headers.pop("Authorization",  None)
            self.session.headers.pop("X-XSRF-TOKEN",   None)

    # -------------------------------------------------------------------------
    # Low-level GET helper
    # -------------------------------------------------------------------------

    def _get(self, path: str, params: dict = None) -> dict:
        """Make an authenticated GET request and return parsed JSON."""
        if not self._jwt_token:
            raise RuntimeError("Not authenticated — call login() first.")
        url  = f"{self.base_url}/dataservice{path}"
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------------------
    # Data fetching methods
    # -------------------------------------------------------------------------

    def get_all_devices(self) -> list:
        """
        GET /dataservice/device
        Returns the full device inventory including reachability, control
        connections, BFD sessions, device state, and software version.
        """
        data = self._get("/device")
        return data.get("data", [])

    def get_vedge_devices(self) -> list:
        """
        GET /dataservice/system/device/vedges
        Returns WAN Edge devices with config-group/template deployment status
        fields: configStatusMessage, templateStatus, configOperationMode.
        """
        data = self._get("/system/device/vedges")
        return data.get("data", [])

    def get_bfd_summary(self, system_ip: str) -> dict:
        """
        GET /dataservice/device/bfd/summary?deviceId=<system-ip>
        Returns BFD session summary with sessions-up, sessions-total, etc.
        """
        try:
            data  = self._get("/device/bfd/summary", params={"deviceId": system_ip})
            items = data.get("data", [])
            return items[0] if items else {}
        except Exception as e:
            return {"_error": str(e)}

    def get_tloc_details(self, system_ip: str) -> list:
        """
        GET /dataservice/device/omp/tlocs/advertised?deviceId=<system-ip>
        Returns TLOCs advertised by this device over OMP, including:
          color, ip (TLOC address), if-name (WAN interface).
        Falls back to /device/bfd/tloc if the OMP endpoint is unavailable.
        """
        try:
            data = self._get("/device/omp/tlocs/advertised",
                             params={"deviceId": system_ip})
            rows = data.get("data", [])
            if rows:
                return rows
        except Exception:
            pass
        # Fallback — BFD TLOC endpoint (has color but no interface)
        try:
            data = self._get("/device/bfd/tloc", params={"deviceId": system_ip})
            return data.get("data", [])
        except Exception:
            return []

    def get_device_counters(self, system_ip: str) -> dict:
        """
        GET /dataservice/device/counters?deviceId=<system-ip>
        Returns OMP peers, control connections, BFD session counts.
        The field "controlConnections" contains the number of UP connections.
        """
        try:
            data  = self._get("/device/counters", params={"deviceId": system_ip})
            items = data.get("data", [])
            return items[0] if items else {}
        except Exception as e:
            return {"_error": str(e)}

    def get_cellular_connection(self, system_ip: str) -> list:
        """
        GET /dataservice/device/cellular/connection?deviceId=<system-ip>
        Returns one row per cellular interface (active and inactive).
        Active interface identified by:
          - cellular-packet-status == "packet-session-status-active"
          - link-uptime != "-"
          - tx-bytes > 0 or rx-bytes > 0
        """
        try:
            data = self._get("/device/cellular/connection",
                             params={"deviceId": system_ip})
            return data.get("data", [])
        except Exception:
            return []

    def get_control_connections(self, system_ip: str) -> list:
        """
        GET /dataservice/device/control/synced/connections?deviceId=<system-ip>
        Returns one row per active control plane connection (vManage, vSmart).
        Each row contains: peer-type, system-ip, site-id, state, uptime.
        Uses the NMS-synced endpoint so it works without direct device SSH.
        """
        try:
            data = self._get("/device/control/synced/connections",
                             params={"deviceId": system_ip})
            return data.get("data", [])
        except Exception:
            return []

    def get_policy_group_for_device(self, device_id: str,
                                        extra_ids: tuple = ()) -> dict:
        """
        Find the policy group assigned to this device.

        GET /dataservice/v1/policy-group returns all groups but with devices:[].
        Must fetch each group individually via GET /v1/policy-group/{id} to get
        the populated devices list, then match on any plausible device identifier.

        Args:
            device_id  : vedge record "id" field (UUID, e.g. "3ea88174-...")
            extra_ids  : additional identifiers to try (chassis uuid, system-ip,
                         serial number — whatever the API stores on the device entry)

        Returns a dict: {name, last_updated, sync_status, id}
        or an empty dict if no policy group is assigned.
        """
        from datetime import datetime, timezone

        all_ids = set(filter(None, (device_id, *extra_ids)))

        try:
            raw    = self._get("/v1/policy-group")
            groups = raw if isinstance(raw, list) else raw.get("data", [])
        except Exception:
            return {}

        for group in groups:
            # Quick skip: no devices attached to this group at all
            if int(group.get("numberOfDevices", 0)) == 0:
                continue
            group_id = group.get("id", "")
            if not group_id:
                continue

            # Fetch full detail to get populated devices list
            try:
                detail  = self._get(f"/v1/policy-group/{group_id}")
                # The detail endpoint may return the group directly or wrap in data
                if isinstance(detail, dict) and "devices" not in detail:
                    detail = detail.get("data", detail)
                devices = detail.get("devices", [])
            except Exception:
                continue

            # Match on ANY plausible identifier field the device entry might use
            matched = False
            for d in devices:
                if not isinstance(d, dict):
                    continue
                dev_values = set(str(v) for v in d.values() if v)
                if dev_values & all_ids:
                    matched = True
                    break

            if matched:
                n_up_to_date = int(group.get("numberOfDevicesUpToDate", 0) or 0)
                n_total      = int(group.get("numberOfDevices",         0) or 0)
                sync_status  = "In Sync" if n_up_to_date == n_total else (
                    f"Out of Sync ({n_up_to_date}/{n_total} up-to-date)"
                )
                ts_ms = group.get("lastUpdatedOn", 0) or 0
                if ts_ms:
                    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
                    last_updated = dt.strftime("%d-%b-%Y %H:%M:%S UTC")
                else:
                    last_updated = "N/A"
                return {
                    "name":         group.get("name", "Unknown"),
                    "last_updated": last_updated,
                    "sync_status":  sync_status,
                    "id":           group_id,
                }
        return {}

    def get_config_group_name(self, template_id: str = "",
                               config_group_id: str = "") -> str:
        """
        Resolve a human-readable name for the assigned configuration group
        or device template.

        UX 2.0 (Config Groups) : GET /dataservice/v1/config-group/{id}
        UX 1.0 (Templates)     : GET /dataservice/template/device
                                  → match by templateId field
        Returns the name string, or the raw ID if lookup fails.
        """
        # ── UX 2.0 config-group ───────────────────────────────────────
        if config_group_id:
            try:
                data = self._get(f"/v1/config-group/{config_group_id}")
                name = (data.get("name")
                        or data.get("data", {}).get("name")
                        or config_group_id)
                return name
            except Exception:
                return config_group_id

        # ── UX 1.0 device template ────────────────────────────────────
        if template_id:
            try:
                data = self._get("/template/device")
                for tmpl in data.get("data", []):
                    if tmpl.get("templateId") == template_id:
                        return tmpl.get("templateName", template_id)
            except Exception:
                pass
            return template_id

        return "None"


# =============================================================================
# Validation Logic
# =============================================================================

class DeviceResult:
    """Holds all validation results for a single device."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NA   = "N/A"

    def __init__(self, hostname: str, serial_number: str, system_ip: str):
        self.hostname       = hostname
        self.serial_number  = serial_number
        self.system_ip      = system_ip
        self.site_id        = ""
        self.site_name      = ""
        self.device_model        = ""
        self.last_deployed_raw   = ""   # ISO-like string for sorting, e.g. "2026-02-24 13:46:25"
        self.checks              = {}   # {check_name: {"status": ..., "value": ..., "detail": ...}}
        self.overall_status = self.PASS
        self.error          = None

    def add_check(self, name: str, status: str, value: str, detail: str = ""):
        self.checks[name] = {
            "status": status,
            "value":  value,
            "detail": detail,
        }
        if status == self.FAIL:
            self.overall_status = self.FAIL
        elif status == self.WARN and self.overall_status != self.FAIL:
            self.overall_status = self.WARN

    def set_error(self, message: str):
        self.error          = message
        self.overall_status = self.FAIL


ALL_CHECK_NAMES = [
    "Config-Group Deployment",
    "Device Reachability",
    "Control Connections",
    "OMP Peers",
    "BFD Sessions (Tunnels)",
    "TLOCs",
    "Device Health",
    "Software Version",
]
if CHECK_CELLULAR:
    ALL_CHECK_NAMES.append("Cellular Status")


def _fill_na(result: DeviceResult, detail: str = "N/A") -> None:
    """Mark all un-filled checks as N/A."""
    for name in ALL_CHECK_NAMES:
        if name not in result.checks:
            result.add_check(name, DeviceResult.NA, DeviceResult.NA, detail)


def validate_device(
    client:        SDWANManagerClient,
    csv_device:    dict,
    all_devices:   list,
    vedge_devices: list,
) -> DeviceResult:
    """Run all staging validation checks for a single device."""

    hostname      = csv_device["hostname"]
    serial_number = csv_device["serial_number"]
    system_ip     = csv_device["system_ip"]
    result        = DeviceResult(hostname, serial_number, system_ip)

    # ---- Locate device in /dataservice/device inventory ----
    inv_device = None
    for d in all_devices:
        if d.get("system-ip") == system_ip or d.get("host-name") == hostname:
            inv_device = d
            break

    if inv_device is None:
        result.set_error(
            f"Device not found in SD-WAN Manager inventory "
            f"(system-ip={system_ip}, hostname={hostname}). "
            "Device may not have completed ZTP onboarding yet."
        )
        _fill_na(result, "Device not found in inventory")
        return result

    # Populate site info from inventory record
    result.site_id   = str(inv_device.get("site-id",   ""))
    result.site_name = str(inv_device.get("site-name", ""))

    # ---- Locate device in /dataservice/system/device/vedges ----
    vedge_device = None
    for d in vedge_devices:
        if (
            d.get("serialNumber") == serial_number
            or d.get("system-ip")  == system_ip
            or d.get("host-name")  == hostname
        ):
            vedge_device = d
            break

    # Populate device model from vedge chasisNumber
    # e.g. "IR1101-K9-FVH2940L812" -> "IR1101-K9"
    if vedge_device:
        chassis = vedge_device.get("chasisNumber", "")
        if chassis:
            parts = chassis.rsplit("-", 1)   # split off last segment (serial)
            result.device_model = parts[0] if len(parts) > 1 else chassis

    # =========================================================================
    # CHECK 1 — Configuration-Group / Template Deployment Status
    # Resolves the template/config-group name and last-deployment timestamp.
    # =========================================================================
    if vedge_device:
        template_status  = vedge_device.get("templateStatus", "")
        config_msg       = vedge_device.get("configStatusMessage", "")
        template_id      = vedge_device.get("templateId", "")
        config_group_id  = vedge_device.get("configGroupId", "")
        apply_log        = vedge_device.get("templateApplyLog", [])

        # ── Resolve name ──────────────────────────────────────────────
        # "managed-by" contains the full label, e.g. "Config-Group BKW-ES200"
        # Strip the well-known prefix to get just the group/template name.
        managed_by = vedge_device.get("managed-by", "")
        if managed_by.lower().startswith("config-group "):
            cg_name = managed_by[len("config-group "):]
        elif managed_by.lower().startswith("template "):
            cg_name = managed_by[len("template "):]
        elif managed_by:
            cg_name = managed_by
        else:
            # Last-resort fallback: try templateId / configGroupId via API
            cg_name = client.get_config_group_name(
                template_id     = template_id,
                config_group_id = config_group_id,
            )

        # ── Extract last-deployed timestamp from apply log ────────────
        # Log entries look like: "[19-Jun-2020 18:47:23 UTC] Sync-from successful"
        last_deployed = "N/A"
        if apply_log and isinstance(apply_log, list):
            last_entry = apply_log[-1]  # most recent entry
            if last_entry.startswith("["):
                try:
                    last_deployed = last_entry[1:last_entry.index("]")]
                except ValueError:
                    last_deployed = last_entry[:40]
            else:
                last_deployed = last_entry[:60]

        # ── Convert last_deployed to a sortable ISO-style string ────────
        last_deployed_iso = ""
        if last_deployed and last_deployed != "N/A":
            import re as _re
            _MONTHS = {"jan":"01","feb":"02","mar":"03","apr":"04","may":"05","jun":"06",
                       "jul":"07","aug":"08","sep":"09","oct":"10","nov":"11","dec":"12"}
            # e.g. "24-Feb-2026 13:46:25 CET" or "24-Feb-2026 13:46:25"
            _m = _re.match(r'(\d{1,2})-(\w{3})-(\d{4})\s+(\d{2}:\d{2}:\d{2})', last_deployed)
            if _m:
                _d, _mo, _y, _t = _m.groups()
                _mo_n = _MONTHS.get(_mo.lower(), "00")
                last_deployed_iso = f"{_y}-{_mo_n}-{_d.zfill(2)} {_t}"
        result.last_deployed_raw = last_deployed_iso

        detail = f"Last deployed: {last_deployed}  |  {config_msg or 'N/A'}"

        if template_status.lower() == "success":
            result.add_check(
                "Config-Group Deployment",
                DeviceResult.PASS,
                cg_name,
                detail,
            )
        elif template_status == "" or template_status.lower() in (
            "not applicable", "none"
        ):
            result.add_check(
                "Config-Group Deployment",
                DeviceResult.WARN,
                "Not assigned",
                "No config-group or template assigned — device may be in CLI mode.",
            )
        else:
            result.add_check(
                "Config-Group Deployment",
                DeviceResult.FAIL,
                cg_name if cg_name != "None" else template_status,
                detail,
            )
    else:
        result.add_check(
            "Config-Group Deployment",
            DeviceResult.WARN,
            DeviceResult.NA,
            "Device not found in vEdge list — cannot verify deployment status.",
        )

    # =========================================================================
    # CHECK 2 — Device Reachability
    # =========================================================================
    reachability = inv_device.get("reachability", "unreachable")
    if reachability == "reachable":
        result.add_check(
            "Device Reachability",
            DeviceResult.PASS,
            "Reachable",
        )
    else:
        if ENFORCE_REACHABILITY:
            # Strict mode: mark FAIL, skip all remaining checks, set overall FAIL
            result.add_check(
                "Device Reachability",
                DeviceResult.FAIL,
                reachability.capitalize(),
                "Device is not reachable — all remaining checks skipped (ENFORCE_REACHABILITY=True).",
            )
            _fill_na(result, "Skipped — device unreachable")
            return result
        else:
            # Permissive mode: record FAIL but continue running all checks
            result.add_check(
                "Device Reachability",
                DeviceResult.FAIL,
                reachability.capitalize(),
                "Device is not reachable from SD-WAN Manager. Continuing checks (ENFORCE_REACHABILITY=False).",
            )

    # =========================================================================
    # CHECK 3 — Control Connections
    # Primary  : GET /device/control/synced/connections  — per-peer detail,
    #            count rows where state == "up".
    # Fallback : "controlConnections" field from /device/counters, then
    #            from the /device inventory record.
    # =========================================================================
    ctrl_connections = client.get_control_connections(system_ip)

    if ctrl_connections:
        # Count only UP connections and build a peer summary for the detail col
        up_peers = [
            c for c in ctrl_connections
            if str(c.get("state", "")).lower() == "up"
        ]
        ctrl_up   = len(up_peers)
        ctrl_total = len(ctrl_connections)
        ctrl_src  = "control/synced/connections"

        # Summarise peer types, e.g. "vManage ×1, vSmart ×2"
        from collections import Counter
        peer_counts = Counter(
            str(c.get("peer-type", c.get("peerType", "unknown"))).lower()
            for c in up_peers
        )
        peer_summary = ", ".join(
            f"{pt} ×{n}" for pt, n in sorted(peer_counts.items())
        ) or "N/A"
        ctrl_detail = (
            f"{ctrl_up} up / {ctrl_total} total  |  {peer_summary}  "
            f"|  min expected: {MIN_CONTROL_CONNECTIONS}"
        )
    else:
        # Fallback 1: /device/counters
        counters = client.get_device_counters(system_ip)
        if "_error" not in counters and counters:
            ctrl_up  = int(counters.get("controlConnections", 0) or 0)
            ctrl_src = "device/counters"
        else:
            # Fallback 2: inventory record
            ctrl_up  = int(inv_device.get("controlConnections", 0) or 0)
            ctrl_src = "device inventory"
        ctrl_total  = ctrl_up
        ctrl_detail = f"min expected: {MIN_CONTROL_CONNECTIONS}"

    if ctrl_up >= MIN_CONTROL_CONNECTIONS:
        result.add_check(
            "Control Connections",
            DeviceResult.PASS,
            f"{ctrl_up} up / {ctrl_total} total",
            ctrl_detail,
        )
    elif ctrl_up > 0:
        result.add_check(
            "Control Connections",
            DeviceResult.WARN,
            f"{ctrl_up} up / {ctrl_total} total",
            f"Below minimum of {MIN_CONTROL_CONNECTIONS}  |  {ctrl_detail}",
        )
    else:
        result.add_check(
            "Control Connections",
            DeviceResult.FAIL,
            f"{ctrl_up} up / {ctrl_total} total",
            f"No control connections UP  |  {ctrl_detail}",
        )

    # =========================================================================
    # CHECK 3b — OMP Peers
    # Source: GET /device/counters — field "ompPeersUp".
    # =========================================================================
    counters_omp = client.get_device_counters(system_ip)
    if "_error" not in counters_omp and counters_omp:
        omp_up   = int(counters_omp.get("ompPeersUp",   0) or 0)
        omp_down = int(counters_omp.get("ompPeersDown", 0) or 0)
        omp_src  = "device/counters"
    else:
        omp_up   = int(inv_device.get("ompPeers", 0) or 0)
        omp_down = 0
        omp_src  = "device inventory"

    omp_total   = omp_up + omp_down
    omp_display = f"{omp_up} up / {omp_total} total"

    if omp_up >= MIN_OMP_PEERS:
        result.add_check(
            "OMP Peers",
            DeviceResult.PASS,
            omp_display,
            f"Minimum expected: {MIN_OMP_PEERS}",
        )
    elif omp_up > 0:
        result.add_check(
            "OMP Peers",
            DeviceResult.WARN,
            omp_display,
            f"Below minimum of {MIN_OMP_PEERS}",
        )
    else:
        result.add_check(
            "OMP Peers",
            DeviceResult.FAIL,
            omp_display,
            "No OMP peers UP — routing policy cannot be distributed",
        )

    # =========================================================================
    # CHECK 4 — BFD Sessions (Tunnels)
    # =========================================================================
    bfd_summary = client.get_bfd_summary(system_ip)

    if "_error" not in bfd_summary and bfd_summary:
        bfd_up    = int(bfd_summary.get("bfd-sessions-up",    0) or 0)
        bfd_total = int(bfd_summary.get("bfd-sessions-total", 0) or 0)
        bfd_src   = "device/bfd/summary"
    else:
        bfd_up    = int(inv_device.get("bfdSessionsUp", 0) or 0)
        bfd_total = int(inv_device.get("bfdSessions",   0) or 0)
        bfd_src   = "device inventory"

    bfd_display = f"{bfd_up} up / {bfd_total} total"

    if bfd_up >= MIN_BFD_SESSIONS_UP:
        result.add_check(
            "BFD Sessions (Tunnels)",
            DeviceResult.PASS,
            bfd_display,
            f"Minimum expected UP: {MIN_BFD_SESSIONS_UP}",
        )
    else:
        # 0 sessions or below configured minimum → WARN in all cases.
        # BFD only forms between WAN edges; a freshly staged device with a
        # single transport and no remote peers will legitimately show 0.
        if bfd_total == 0:
            detail = (
                f"No BFD peers yet — min expected: {MIN_BFD_SESSIONS_UP}"
            )
        else:
            detail = (
                f"Below minimum of {MIN_BFD_SESSIONS_UP} UP"
            )
        result.add_check(
            "BFD Sessions (Tunnels)",
            DeviceResult.WARN,
            bfd_display,
            detail,
        )

    # =========================================================================
    # CHECK 5 — TLOCs
    # Uses GET /device/omp/tlocs/advertised.
    # The API returns one row per (TLOC, vSmart-peer) combination — the same
    # TLOC is repeated for each vSmart it is advertised to (to-peer differs).
    # De-duplicate by (color, tloc-private-ip) to count unique transports.
    # Shows: color + TLOC private IP address (tloc-private-ip field).
    # =========================================================================
    tloc_rows = client.get_tloc_details(system_ip)

    # Build de-duplicated list of unique TLOCs
    seen  = set()
    tlocs = []
    for row in tloc_rows:
        color    = row.get("color") or row.get("local-color") or "?"
        tloc_ip  = row.get("tloc-private-ip") or row.get("ip") or ""
        key = (color, tloc_ip)
        if key not in seen:
            seen.add(key)
            tlocs.append({"color": color, "ip": tloc_ip})

    tloc_count = len(tlocs)

    # Optional color validation — runs only when EXPECTED_TLOC_COLORS is set.
    # Finds which expected colors are absent from the device's advertised TLOCs.
    actual_colors   = {t["color"] for t in tlocs}
    missing_colors  = []
    if EXPECTED_TLOC_COLORS:
        missing_colors = [c for c in EXPECTED_TLOC_COLORS if c not in actual_colors]

    if tloc_count >= MIN_TLOCS:
        # Value column: "lte / 10.35.214.253, mpls / 10.35.214.254"
        tloc_labels = ", ".join(
            f"{t['color']} / {t['ip']}" if t["ip"] else t["color"]
            for t in tlocs
        ) or "see device detail"
        # Detail column: one entry per TLOC
        tloc_detail_lines = "  |  ".join(
            f"[{i+1}] color: {t['color']}  ip: {t['ip'] or 'N/A'}"
            for i, t in enumerate(tlocs)
        )
        base_detail = f"{tloc_detail_lines}  |  min expected: {MIN_TLOCS}"
        if missing_colors:
            # Count/min satisfied but required colors missing → WARN
            result.add_check(
                "TLOCs",
                DeviceResult.WARN,
                f"{tloc_count}  ({tloc_labels})",
                f"{base_detail}  |  missing colors: {', '.join(missing_colors)}",
            )
        else:
            result.add_check(
                "TLOCs",
                DeviceResult.PASS,
                f"{tloc_count}  ({tloc_labels})",
                base_detail + (
                    f"  |  expected colors: {', '.join(EXPECTED_TLOC_COLORS)}"
                    if EXPECTED_TLOC_COLORS else ""
                ),
            )
    elif tloc_count == 0:
        result.add_check(
            "TLOCs",
            DeviceResult.FAIL,
            "0",
            "No TLOCs advertised — overlay tunnels cannot form",
        )
    else:
        tloc_labels = ", ".join(
            f"{t['color']} / {t['ip']}" if t["ip"] else t["color"]
            for t in tlocs
        )
        missing_detail = (
            f"  |  missing colors: {', '.join(missing_colors)}" if missing_colors else ""
        )
        result.add_check(
            "TLOCs",
            DeviceResult.WARN,
            f"{tloc_count}  ({tloc_labels})",
            f"Below minimum of {MIN_TLOCS} expected{missing_detail}",
        )

    # =========================================================================
    # CHECK 6 — Device Health State
    # =========================================================================
    state      = inv_device.get("state", "").lower()
    state_desc = inv_device.get("state_description", "")

    if state == "green":
        result.add_check(
            "Device Health",
            DeviceResult.PASS,
            "Green ✓",
            "Healthy",
        )
    elif state == "yellow":
        result.add_check(
            "Device Health",
            DeviceResult.WARN,
            "Yellow △",
            state_desc or "Some issues detected — review device dashboard",
        )
    else:
        result.add_check(
            "Device Health",
            DeviceResult.FAIL,
            f"{state.capitalize()} ✗" if state else "Unknown ✗",
            state_desc or "Device health is degraded or unknown",
        )

    # =========================================================================
    # CHECK 7 — Software Version
    # =========================================================================
    version = inv_device.get("version", "Unknown")

    if EXPECTED_SW_VERSION is None:
        result.add_check(
            "Software Version",
            DeviceResult.PASS,
            version,
            "No target version configured (EXPECTED_SW_VERSION is None)",
        )
    elif version == EXPECTED_SW_VERSION:
        result.add_check(
            "Software Version",
            DeviceResult.PASS,
            version,
            f"Matches expected version: {EXPECTED_SW_VERSION}",
        )
    else:
        result.add_check(
            "Software Version",
            DeviceResult.FAIL,
            version,
            f"Expected: {EXPECTED_SW_VERSION} — Actual: {version}",
        )

    # =========================================================================
    # CHECK 8 — Cellular Status  (only when CHECK_CELLULAR = True)
    # Source: GET /device/cellular/connection
    # Active interface: packet-session-status-active AND (uptime != "-" OR
    #                   tx-bytes > 0 OR rx-bytes > 0)
    # =========================================================================
    if CHECK_CELLULAR:
        cell_rows = client.get_cellular_connection(system_ip)

        # Determine which interface is active using all available signals
        active_cell = None
        for row in cell_rows:
            is_active_status = (
                row.get("cellular-packet-status", "") == "packet-session-status-active"
            )
            uptime_ok  = row.get("link-uptime", "-") not in ("-", "", None)
            tx_ok      = int(row.get("tx-bytes", 0) or 0) > 0
            rx_ok      = int(row.get("rx-bytes", 0) or 0) > 0
            if is_active_status or uptime_ok or tx_ok or rx_ok:
                active_cell = row
                break   # take first match

        if not cell_rows:
            # API returned nothing — endpoint unavailable or not a cellular device
            result.add_check(
                "Cellular Status",
                DeviceResult.NA,
                "No data",
                "No cellular connection data returned — device may not have a cellular interface.",
            )
        elif active_cell:
            iface   = active_cell.get("cellular-interface", "N/A")
            apn     = active_cell.get("profile-apn",        "N/A")
            ipv4    = active_cell.get("ipv4-addr",          "N/A")
            uptime  = active_cell.get("link-uptime",        "N/A")
            profile = active_cell.get("active-profile",     "N/A")
            detail  = (
                f"Interface: {iface}  |  APN: {apn}  |  "
                f"IPv4: {ipv4}  |  Profile: {profile}  |  Uptime: {uptime}"
            )
            result.add_check(
                "Cellular Status",
                DeviceResult.PASS,
                "Active ✓",
                detail,
            )
        else:
            # Interfaces found but none is active
            ifaces = ", ".join(
                r.get("cellular-interface", "?") for r in cell_rows
            )
            result.add_check(
                "Cellular Status",
                DeviceResult.FAIL,
                "No active interface",
                f"All interfaces inactive: {ifaces}",
            )

    return result


# =============================================================================
# CSV Reader
# =============================================================================

def read_devices_from_csv(csv_path: str) -> list:
    """
    Read device list from a CSV file.
    Required columns (case-insensitive): hostname, serial_number, system_ip
    """
    devices = []
    path    = Path(csv_path)
    if not path.exists():
        print(f"[!] CSV file not found: {csv_path}")
        sys.exit(1)

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # Normalise headers: lowercase + underscores
        reader.fieldnames = [
            h.strip().lower().replace(" ", "_") for h in reader.fieldnames
        ]
        required = {"hostname", "serial_number", "system_ip"}
        missing  = required - set(reader.fieldnames)
        if missing:
            print(f"[!] CSV is missing required column(s): {missing}")
            print(f"    Columns found: {reader.fieldnames}")
            print("    Required format: hostname,serial_number,system_ip")
            sys.exit(1)

        for row in reader:
            devices.append({
                "hostname":      row["hostname"].strip(),
                "serial_number": row["serial_number"].strip(),
                "system_ip":     row["system_ip"].strip(),
            })

    print(f"[+] Loaded {len(devices)} device(s) from {csv_path}")
    return devices


def _device_has_tag(inv_device: dict, tag_name: str) -> bool:
    """
    Check whether a /dataservice/device inventory record carries a given tag.
    Tags are stored as: "tags": [{"name": "staging", "type": "USER", ...}, ...]
    """
    tags = inv_device.get("tags", [])
    if not isinstance(tags, list):
        return False
    return any(
        isinstance(t, dict) and t.get("name", "").lower() == tag_name.lower()
        for t in tags
    )


def read_devices_from_manager(client: "SDWANManagerClient",
                               all_devices: list,
                               vedge_devices: list) -> list:
    """
    Build the device list dynamically from the Manager inventory.
    SCOPE = "all"     → return every registered WAN Edge device.
    SCOPE = "staging" → return only devices whose inventory record
                        carries the STAGING_TAG tag (field: "tags").

    Tags are read from the "tags" field of GET /dataservice/device —
    no separate API call is required.

    Returns a list of dicts with keys: hostname, serial_number, system_ip
    (same schema as read_devices_from_csv, so validate_device() is unchanged).
    """
    if SCOPE.lower() == "staging":
        # Filter inventory to devices carrying the staging tag
        tagged = [d for d in all_devices if _device_has_tag(d, STAGING_TAG)]
        print(f"[*] Filtering by tag \"{STAGING_TAG}\" from inventory ...")
        print(f"    → {len(tagged)} device(s) carry tag \"{STAGING_TAG}\".")
        if not tagged:
            print(f"[!] No devices found with tag \"{STAGING_TAG}\". "
                  f"Assign the tag in SD-WAN Manager and retry.")
            sys.exit(1)
        source = tagged
    else:
        source = all_devices   # all WAN Edge devices

    # Build a serial → system-ip lookup from the vedge list for fallback
    vedge_by_hostname = {v.get("host-name", ""): v for v in vedge_devices}

    devices = []
    for inv in source:
        hostname  = (inv.get("host-name") or inv.get("hostname") or "").strip()
        system_ip = (inv.get("system-ip") or inv.get("deviceId") or "").strip()
        # Serial: prefer board-serial from inventory; fall back to vedge record
        serial = (inv.get("board-serial") or "").strip()
        if not serial:
            vedge = vedge_by_hostname.get(hostname, {})
            serial = (vedge.get("serialNumber") or "").strip()

        if not system_ip or not hostname:
            continue   # skip incomplete records

        devices.append({
            "hostname":      hostname,
            "serial_number": serial,
            "system_ip":     system_ip,
        })

    return devices


# =============================================================================
# HTML Report Generator
# =============================================================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cisco Catalyst SD-WAN — Staging Validation Report</title>
  <style>
    :root {
      --pass:   #1abc9c;
      --fail:   #e74c3c;
      --warn:   #f39c12;
      --na:     #95a5a6;
      --bg:     #0d1117;
      --card:   #161b22;
      --border: #30363d;
      --text:   #c9d1d9;
      --head:   #e6edf3;
      --cisco:  #049fd9;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 28px 24px;
    }

    /* ── Header ─────────────────────────────────── */
    .rpt-header {
      display: flex;
      align-items: center;
      gap: 18px;
      padding-bottom: 22px;
      margin-bottom: 28px;
      border-bottom: 1px solid var(--border);
    }
    .cisco-logo {
      display: flex;
      align-items: center;
      flex-shrink: 0;
    }
    .cisco-logo img { display: block; height: 48px; width: auto; }
    .rpt-title h1 {
      font-size: 21px;
      font-weight: 600;
      color: var(--head);
    }
    .rpt-title p  {
      font-size: 12.5px;
      color: #768390;
      margin-top: 5px;
    }

    /* ── Summary Bar ─────────────────────────────── */
    .summary-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 14px;
      margin-bottom: 30px;
    }
    .sum-card {
      flex: 1;
      min-width: 130px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px 20px;
      text-align: center;
    }
    .sum-card { cursor: pointer; transition: box-shadow 0.15s, transform 0.15s; }
    .sum-card:hover { box-shadow: 0 0 0 2px rgba(255,255,255,.18); transform: translateY(-1px); }
    .sum-card.active { box-shadow: 0 0 0 2px var(--cisco); }
    .sum-card .num   { font-size: 38px; font-weight: 700; line-height: 1; }
    .sum-card .lbl   { font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; margin-top: 7px; opacity: 0.7; }
    .c-total { color: var(--cisco); }
    .c-pass  { color: var(--pass);  }
    .c-fail  { color: var(--fail);  }
    .c-warn  { color: var(--warn);  }

    /* ── Device Card ─────────────────────────────── */
    .dev-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 26px;
      overflow: hidden;
    }
    .dev-card-hdr {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      padding: 15px 20px;
      border-bottom: 1px solid var(--border);
    }
    .dev-hostname {
      font-size: 16px;
      font-weight: 600;
      color: var(--head);
    }
    .badge {
      font-size: 10.5px;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 20px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-pass { background: rgba(26,188,156,.18); color: var(--pass); }
    .badge-fail { background: rgba(231,76,60,.18);  color: var(--fail); }
    .badge-warn { background: rgba(243,156,18,.18); color: var(--warn); }
    .badge-na   { background: rgba(149,165,166,.1); color: var(--na);   }
    .spacer { flex: 1; }
    .dev-sysip { font-size: 12px; color: #768390; font-family: monospace; }

    .dev-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 22px;
      padding: 10px 20px;
      background: rgba(255,255,255,.025);
      border-bottom: 1px solid var(--border);
      font-size: 12px;
    }
    .dev-meta strong { color: var(--head); }

    .err-banner {
      padding: 11px 20px;
      background: rgba(231,76,60,.1);
      border-bottom: 1px solid rgba(231,76,60,.3);
      color: #ff7b72;
      font-size: 13px;
    }

    /* ── Check Table ─────────────────────────────── */
    table { width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }
    thead th {
      background: rgba(255,255,255,.035);
      color: var(--head);
      font-weight: 600;
      padding: 9px 16px;
      text-align: left;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      border-bottom: 1px solid var(--border);
    }
    tbody tr   { border-bottom: 1px solid rgba(48,54,61,.6); }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: rgba(255,255,255,.02); }
    tbody td   { padding: 10px 16px; vertical-align: top; overflow-wrap: break-word; }

    .chk-name  { color: var(--head); font-weight: 500; }
    .chk-value { font-family: "Cascadia Code","Consolas",monospace; font-size: 12.5px; }
    .chk-detail { color: #768390; font-size: 12px; }

    /* ── Collapse / Expand ───────────────────── */
    .dev-body { display: none; }
    .dev-card.expanded .dev-body { display: block; }

    .toggle-btn {
      background: none;
      border: none;
      cursor: pointer;
      padding: 0 4px;
      color: #768390;
      font-size: 13px;
      line-height: 1;
      transition: transform 0.2s ease;
      display: inline-flex;
      align-items: center;
    }
    .dev-card.expanded .toggle-btn { transform: rotate(90deg); }
    .dev-card-hdr { cursor: pointer; user-select: none; }
    .dev-card-hdr:hover { background: rgba(255,255,255,.025); }

    /* ── Expand-all bar ─────────────────────── */
    .expand-bar {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 18px;
      flex-wrap: wrap;
    }
    .expand-bar button {
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      color: var(--head);
      border-radius: 6px;
      padding: 6px 16px;
      font-size: 12px;
      cursor: pointer;
    }
    .expand-bar button:hover { background: rgba(255,255,255,.12); }
    .expand-bar button.active-toggle {
      background: rgba(220,80,80,.18);
      border-color: #e05555;
      color: #f08080;
    }
    .expand-bar button.active-toggle:hover { background: rgba(220,80,80,.28); }
    .search-wrap {
      margin-left: auto;
      position: relative;
      display: flex;
      align-items: center;
    }
    .search-wrap svg {
      position: absolute;
      left: 10px;
      opacity: 0.45;
      pointer-events: none;
    }
    #deviceSearch {
      background: rgba(255,255,255,.06);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--head);
      font-size: 13px;
      padding: 6px 12px 6px 34px;
      width: 280px;
      outline: none;
      transition: border-color 0.15s;
    }
    #deviceSearch::placeholder { color: rgba(255,255,255,.3); }
    #deviceSearch:focus { border-color: var(--cisco); }
    #searchCount {
      font-size: 11px;
      color: rgba(255,255,255,.4);
      margin-left: 8px;
      white-space: nowrap;
    }

    .pill {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 20px;
      font-size: 10.5px;
      font-weight: 700;
      letter-spacing: 0.4px;
      white-space: nowrap;
    }
    .pill-PASS { background: rgba(26,188,156,.14); color: var(--pass); border: 1px solid rgba(26,188,156,.4); }
    .pill-FAIL { background: rgba(231,76,60,.14);  color: var(--fail); border: 1px solid rgba(231,76,60,.4);  }
    .pill-WARN { background: rgba(243,156,18,.14); color: var(--warn); border: 1px solid rgba(243,156,18,.4); }
    .pill-NA   { background: rgba(149,165,166,.1); color: var(--na);   border: 1px solid rgba(149,165,166,.3); }

    /* ── Footer ──────────────────────────────────── */
    .footer {
      text-align: center;
      font-size: 11px;
      color: #4a5568;
      margin-top: 40px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
    }
  </style>
</head>
<body>

  <!-- ── Header ── -->
  <div class="rpt-header">
    <div class="cisco-logo">
      <img src="data:image/png;base64,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" alt="Cisco" />
    </div>
    <div class="rpt-title">
      <h1>Catalyst SD-WAN &mdash; Staging Validation Report</h1>
      <p>Generated: <strong>{{ generated_at }}</strong> &nbsp;&bull;&nbsp; Manager: <strong>{{ vmanage_host }}</strong> &nbsp;&bull;&nbsp; Devices tested: <strong>{{ total }}</strong></p>
    </div>
  </div>

  <!-- ── Summary ── -->
  <div class="summary-bar">
    <div class="sum-card" onclick="filterCards('all', this)"><div class="num c-total">{{ total }}</div><div class="lbl">Total Devices</div></div>
    <div class="sum-card" onclick="filterCards('PASS', this)"><div class="num c-pass">{{ passed }}</div><div class="lbl">All Checks Passed</div></div>
    <div class="sum-card" onclick="filterCards('FAIL', this)"><div class="num c-fail">{{ failed }}</div><div class="lbl">Checks Failed</div></div>
    <div class="sum-card" onclick="filterCards('WARN', this)"><div class="num c-warn">{{ warned }}</div><div class="lbl">Warnings</div></div>
  </div>

  <!-- ── Toolbar: Expand / Collapse + Search ── -->
  <div class="expand-bar">
    <button onclick="toggleAll(true)">&#9654; Expand All</button>
    <button onclick="toggleAll(false)">&#9664; Collapse All</button>
    <button id="btnHideUnreachable" onclick="toggleUnreachable(this)">&#128683; Hide Unreachable</button>
    <div class="search-wrap">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      <input id="deviceSearch" type="text" placeholder="Search hostname, IP, serial, site…"
             oninput="searchDevices(this.value)" autocomplete="off" />
      <span id="searchCount"></span>
    </div>
  </div>

  <!-- ── Device Results ── -->
  {% for dev in devices %}
  <div class="dev-card"
       data-status="{{ dev.overall_status }}"
       data-reachable="{{ '0' if dev.checks.get('Device Reachability', {}).get('status') == 'FAIL' else '1' }}"
       data-search="{{ (dev.hostname ~ " " ~ dev.system_ip ~ " " ~ dev.serial_number ~ " " ~ dev.site_name ~ " " ~ dev.site_id ~ " " ~ dev.device_model) | lower }}"
       onclick="toggleCard(this)">
    <div class="dev-card-hdr">
      <button class="toggle-btn" onclick="event.stopPropagation(); toggleCard(this.closest('.dev-card'))">&#9654;</button>
      <span class="dev-hostname">{{ dev.hostname }}</span>
      <span class="badge badge-{{ dev.overall_status | lower }}">{{ dev.overall_status }}</span>
      <span class="spacer"></span>
      <span class="dev-sysip">{{ dev.system_ip }}</span>
    </div>

    <div class="dev-meta">
      <span><strong>System IP:</strong> {{ dev.system_ip }}</span>
      <span><strong>Serial Number:</strong> {{ dev.serial_number }}</span>
      {% if dev.device_model %}<span><strong>Device Model:</strong> {{ dev.device_model }}</span>{% endif %}
      {% if dev.site_id %}<span><strong>Site ID:</strong> {{ dev.site_id }}</span>{% endif %}
      {% if dev.site_name %}<span><strong>Site Name:</strong> {{ dev.site_name }}</span>{% endif %}
    </div>

    <div class="dev-body">
      {% if dev.error %}
      <div class="err-banner">&#9888;&nbsp; {{ dev.error }}</div>
      {% endif %}

      <table>
        <thead>
          <tr>
            <th style="width:200px;">Check</th>
            <th style="width:90px;">Status</th>
            <th style="width:300px;">Value</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {% for name, chk in dev.checks.items() %}
          <tr>
            <td class="chk-name">{{ name }}</td>
            <td>
              {% if chk.status == "PASS" %}<span class="pill pill-PASS">PASS</span>
              {% elif chk.status == "FAIL" %}<span class="pill pill-FAIL">FAIL</span>
              {% elif chk.status == "WARN" %}<span class="pill pill-WARN">WARN</span>
              {% else %}<span class="pill pill-NA">N/A</span>
              {% endif %}
            </td>
            <td class="chk-value">{{ chk.value }}</td>
            <td class="chk-detail">{{ chk.detail }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endfor %}

  <div class="footer">
    Cisco Catalyst SD-WAN Staging Validator &nbsp;&bull;&nbsp;
    {{ generated_at }}
  </div>

  <script>
    function toggleCard(card) {
      card.classList.toggle("expanded");
    }
    function toggleAll(expand) {
      document.querySelectorAll(".dev-card").forEach(function(card) {
        if (expand) card.classList.add("expanded");
        else card.classList.remove("expanded");
      });
    }

    // ── Central visibility state ──────────────────────────────────────
    var activeFilter      = "all";
    var hideUnreachable   = false;

    function applyVisibility() {
      var searchEl = document.getElementById("deviceSearch");
      var q = searchEl ? searchEl.value.trim().toLowerCase() : "";
      var shown = 0;
      document.querySelectorAll(".dev-card").forEach(function(card) {
        var statusMatch     = (activeFilter === "all" || card.getAttribute("data-status") === activeFilter);
        var textMatch       = (q === "" || (card.getAttribute("data-search") || "").indexOf(q) !== -1);
        var reachableMatch  = (!hideUnreachable || card.getAttribute("data-reachable") === "1");
        var visible = statusMatch && textMatch && reachableMatch;
        card.style.display = visible ? "" : "none";
        if (visible) shown++;
      });
      var countEl = document.getElementById("searchCount");
      if (countEl) countEl.textContent = q ? shown + " result" + (shown !== 1 ? "s" : "") : "";
    }

    function searchDevices(query) {
      applyVisibility();
    }

    function filterCards(status, btn) {
      if (activeFilter === status && status !== "all") status = "all";
      activeFilter = status;
      document.querySelectorAll(".sum-card").forEach(function(c) { c.classList.remove("active"); });
      if (btn) btn.classList.add("active");
      if (status === "all" && btn) btn.classList.remove("active");
      applyVisibility();
    }

    function toggleUnreachable(btn) {
      hideUnreachable = !hideUnreachable;
      btn.classList.toggle("active-toggle", hideUnreachable);
      btn.innerHTML = hideUnreachable
        ? "&#128683; Show Unreachable"
        : "&#128683; Hide Unreachable";
      applyVisibility();
    }
  </script>
</body>
</html>
"""


def generate_html_report(results: list, output_path: str) -> None:
    """Render the Jinja2 HTML template and write the report to disk."""
    passed = sum(1 for r in results if r.overall_status == DeviceResult.PASS)
    failed = sum(1 for r in results if r.overall_status == DeviceResult.FAIL)
    warned = sum(1 for r in results if r.overall_status == DeviceResult.WARN)

    devices_data = [
        {
            "hostname":          r.hostname,
            "serial_number":     r.serial_number,
            "system_ip":         r.system_ip,
            "site_id":           r.site_id,
            "site_name":         r.site_name,
            "device_model":      r.device_model,
            "last_deployed_raw": r.last_deployed_raw,
            "overall_status":    r.overall_status,
            "error":             r.error,
            "checks":            r.checks,
        }
        for r in results
    ]

    # Sort by most recent Config-Group deployment (devices with no date sink to bottom)
    devices_data.sort(
        key=lambda d: d["last_deployed_raw"] or "0000-00-00 00:00:00",
        reverse=True
    )

    html = Template(HTML_TEMPLATE).render(
        generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        vmanage_host  = VMANAGE_HOST,
        total         = len(results),
        passed        = passed,
        failed        = failed,
        warned        = warned,
        devices       = devices_data,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] HTML report saved to: {output_path}")



# =============================================================================
# Debug helper — dumps raw API field names for the first CSV device
# =============================================================================

def _dump_debug_fields(
    client:        SDWANManagerClient,
    csv_devices:   list,
    all_devices:   list,
    vedge_devices: list,
) -> None:
    """
    Print raw field names and values from every relevant API response for
    the first device in the CSV.  Run with --debug-fields to diagnose
    unexpected N/A values in the report.
    """
    import json as _json

    if not csv_devices:
        print("[!] No devices in CSV.")
        return

    dev       = csv_devices[0]
    system_ip = dev["system_ip"]
    hostname  = dev["hostname"]
    serial    = dev["serial_number"]

    SEP = "─" * 70

    print(f"\n{'='*70}")
    print(f"  DEBUG FIELD DUMP  —  {hostname}  ({system_ip})")
    print(f"{'='*70}\n")

    # ── /dataservice/device inventory record ────────────────────────
    print(SEP)
    print("  [1]  /dataservice/device  (inventory record)")
    print(SEP)
    inv = next(
        (d for d in all_devices
         if d.get("system-ip") == system_ip or d.get("host-name") == hostname),
        None,
    )
    if inv:
        for k, v in sorted(inv.items()):
            print(f"       {k:<40} = {_json.dumps(v)[:120]}")
    else:
        print("       (device not found in inventory)")

    # ── /dataservice/system/device/vedges record ─────────────────────
    print(f"\n{SEP}")
    print("  [2]  /dataservice/system/device/vedges  (vedge record)")
    print(SEP)
    vedge = next(
        (d for d in vedge_devices
         if d.get("serialNumber") == serial
         or d.get("system-ip")    == system_ip
         or d.get("host-name")    == hostname),
        None,
    )
    if vedge:
        for k, v in sorted(vedge.items()):
            print(f"       {k:<40} = {_json.dumps(v)[:120]}")
    else:
        print("       (device not found in vedge list)")

    # ── /dataservice/device/control/synced/connections ───────────────
    print(f"\n{SEP}")
    print("  [3]  /dataservice/device/control/synced/connections")
    print(SEP)
    ctrl = client.get_control_connections(system_ip)
    if ctrl:
        print(f"       ({len(ctrl)} connection(s) returned)")
        for i, row in enumerate(ctrl[:5], 1):
            print(f"\n       --- connection {i} ---")
            for k, v in sorted(row.items()):
                print(f"       {k:<40} = {_json.dumps(v)[:120]}")
    else:
        print("       (no data returned)")

    # ── /dataservice/device/omp/tlocs/advertised ─────────────────────
    print(f"\n{SEP}")
    print("  [4]  /dataservice/device/omp/tlocs/advertised")
    print(SEP)
    try:
        raw = client._get("/device/omp/tlocs/advertised",
                          params={"deviceId": system_ip})
        tloc_rows = raw.get("data", [])
        if tloc_rows:
            print(f"       ({len(tloc_rows)} row(s) returned)")
            for i, row in enumerate(tloc_rows[:5], 1):
                print(f"\n       --- row {i} ---")
                for k, v in sorted(row.items()):
                    print(f"       {k:<40} = {_json.dumps(v)[:120]}")
        else:
            print("       (empty data array — trying fallback /device/bfd/tloc)")
            raw2     = client._get("/device/bfd/tloc",
                                   params={"deviceId": system_ip})
            bfd_rows = raw2.get("data", [])
            if bfd_rows:
                print(f"       ({len(bfd_rows)} row(s) from bfd/tloc fallback)")
                for i, row in enumerate(bfd_rows[:5], 1):
                    print(f"\n       --- row {i} ---")
                    for k, v in sorted(row.items()):
                        print(f"       {k:<40} = {_json.dumps(v)[:120]}")
            else:
                print("       (no data from bfd/tloc either)")
    except Exception as exc:
        print(f"       (error: {exc})")

    # ── /dataservice/device/counters ─────────────────────────────────
    print(f"\n{SEP}")
    print("  [5]  /dataservice/device/counters")
    print(SEP)
    counters = client.get_device_counters(system_ip)
    if counters and "_error" not in counters:
        for k, v in sorted(counters.items()):
            print(f"       {k:<40} = {_json.dumps(v)[:120]}")
    else:
        print(f"       (no data or error: {counters})")

    # ── /dataservice/device/bfd/summary ───────────────────────────────
    print(f"\n{SEP}")
    print("  [6]  /dataservice/device/bfd/summary")
    print(SEP)
    try:
        raw = client._get("/device/bfd/summary", params={"deviceId": system_ip})
        rows = raw.get("data", [])
        if rows:
            print(f"       ({len(rows)} row(s) returned)")
            for k, v in sorted(rows[0].items()):
                print(f"       {k:<40} = {_json.dumps(v)[:120]}")
        else:
            print("       (empty — no BFD summary data)")
    except Exception as exc:
        print(f"       (error: {exc})")

    # ── /dataservice/device/bfd/sessions (first 2 rows) ──────────────
    print(f"\n{SEP}")
    print("  [7]  /dataservice/device/bfd/sessions  (first 2 rows)")
    print(SEP)
    try:
        raw = client._get("/device/bfd/sessions", params={"deviceId": system_ip})
        rows = raw.get("data", [])
        if rows:
            print(f"       ({len(rows)} session(s) total)")
            for i, row in enumerate(rows[:2], 1):
                print(f"\n       --- session {i} ---")
                for k, v in sorted(row.items()):
                    print(f"       {k:<40} = {_json.dumps(v)[:120]}")
        else:
            print("       (empty — no BFD sessions)")
    except Exception as exc:
        print(f"       (error: {exc})")

    # ── Policy Group — /dataservice/v1/policy-group ───────────────────
    # Try to find any policy group associated with this device.
    print(f"\n{SEP}")
    print("  [8]  /dataservice/v1/policy-group  (all policy groups)")
    print(SEP)
    try:
        raw = client._get("/v1/policy-group")
        groups = raw if isinstance(raw, list) else raw.get("data", raw.get("policyGroups", []))
        if groups:
            print(f"       ({len(groups)} policy group(s) found — showing first 3)")
            for i, g in enumerate(groups[:3], 1):
                print(f"\n       --- policy group {i} ---")
                for k, v in sorted(g.items()) if isinstance(g, dict) else []:
                    print(f"       {k:<40} = {_json.dumps(v)[:120]}")
        else:
            print("       (no policy groups found or empty response)")
            print(f"       raw response keys: {list(raw.keys()) if isinstance(raw, dict) else type(raw)}")
    except Exception as exc:
        print(f"       (error: {exc})")

    # ── Policy Group — /dataservice/template/policy/vedge/attached ────
    # Alternative: check template/policy endpoint for attached policies.
    print(f"\n{SEP}")
    print("  [9]  /dataservice/template/policy/vedge/attached")
    print(SEP)
    try:
        raw = client._get("/template/policy/vedge/attached", params={"deviceId": system_ip})
        rows = raw.get("data", []) if isinstance(raw, dict) else raw
        if rows:
            print(f"       ({len(rows)} row(s) returned — showing first)")
            for k, v in sorted(rows[0].items()) if isinstance(rows[0], dict) else []:
                print(f"       {k:<40} = {_json.dumps(v)[:120]}")
        else:
            print("       (empty)")
    except Exception as exc:
        print(f"       (error: {exc})")

    # ── Vedge record — full templateApplyLog (untruncated) ───────────
    print(f"\n{SEP}")
    print("  [10] templateApplyLog from vedge record (full, untruncated)")
    print(SEP)
    if vedge:
        apply_log = vedge.get("templateApplyLog", [])
        if apply_log:
            for entry in apply_log:
                print(f"       {entry}")
        else:
            print("       (empty)")
    else:
        print("       (vedge record not found)")

    print(f"\n{'='*70}\n")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description  = "Cisco Catalyst SD-WAN Staging Validation Script",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
CSV file format (header row required — order does not matter):
  hostname,serial_number,system_ip

Example rows:
  BR-RTR-01,FDO2349A0BC,10.0.1.1
  BR-RTR-02,FDO2349A0BD,10.0.1.2
  HQ-RTR-01,FDO9999X001,10.0.0.1
        """,
    )
    parser.add_argument(
        "--csv",
        required = False,
        default  = None,
        metavar  = "DEVICES.CSV",
        help     = "Path to CSV file (CSV mode). "
                   "Omit to use Manager-driven mode (controlled by SCOPE config variable).",
    )
    parser.add_argument(
        "--output",
        default = OUTPUT_HTML,
        metavar = "REPORT.HTML",
        help    = f"Output HTML report filename (default: {OUTPUT_HTML})",
    )
    parser.add_argument(
        "--debug-fields",
        action  = "store_true",
        help    = "Dump raw API field names for the first device and exit. "
                  "Use this to diagnose unexpected N/A values.",
    )
    args = parser.parse_args()

    # ── Banner ──
    # ── Determine operating mode ──
    csv_mode = args.csv is not None
    if csv_mode:
        mode_label = f"CSV  ({args.csv})"
    elif SCOPE.lower() == "staging":
        mode_label = f"Manager / STAGING  (tag: \"{STAGING_TAG}\")"
    else:
        mode_label = "Manager / ALL  (every registered WAN Edge)"

    print("=" * 65)
    print("  Cisco Catalyst SD-WAN — Staging Validation Tool")
    print("=" * 65)
    print(f"  Manager   : {VMANAGE_HOST}:{VMANAGE_PORT}")
    print(f"  SSL Verify: {'Disabled (untrusted cert mode)' if DISABLE_SSL_VERIFY else 'Enabled'}")
    print(f"  Mode      : {mode_label}")
    print(f"  Output    : {args.output}")
    print("=" * 65 + "\n")

    # ── Connect to SD-WAN Manager ──
    client = SDWANManagerClient(
        host       = VMANAGE_HOST,
        port       = VMANAGE_PORT,
        username   = VMANAGE_USERNAME,
        password   = VMANAGE_PASSWORD,
        verify_ssl = not DISABLE_SSL_VERIFY,
    )

    try:
        client.login()
    except Exception as e:
        print(f"[!] Authentication failed: {e}")
        sys.exit(1)

    # ── Bulk-fetch inventory data (efficient — 2 API calls total) ──
    print("\n[*] Fetching device inventory (GET /dataservice/device) ...")
    try:
        all_devices = client.get_all_devices()
        print(f"    → {len(all_devices)} device(s) in fabric.")
    except Exception as e:
        print(f"[!] Failed to fetch device inventory: {e}")
        all_devices = []

    print("[*] Fetching WAN Edge list (GET /dataservice/system/device/vedges) ...")
    try:
        vedge_devices = client.get_vedge_devices()
        print(f"    → {len(vedge_devices)} WAN Edge device(s) found.")
    except Exception as e:
        print(f"[!] Failed to fetch vEdge list: {e}")
        vedge_devices = []

    # ── Load device list (CSV or Manager-driven) ──
    if csv_mode:
        csv_devices = read_devices_from_csv(args.csv)
    else:
        csv_devices = read_devices_from_manager(client, all_devices, vedge_devices)
        scope_desc = (
            f"tag \"{STAGING_TAG}\"" if SCOPE.lower() == "staging"
            else "all WAN Edge devices"
        )
        print(f"[+] {len(csv_devices)} device(s) selected from Manager ({scope_desc}).")
        if not csv_devices:
            print("[!] No devices to validate. Exiting.")
            client.logout()
            sys.exit(0)

    # ── Debug-fields mode ──
    if args.debug_fields:
        _dump_debug_fields(client, csv_devices, all_devices, vedge_devices)
        client.logout()
        sys.exit(0)

    # ── Per-device validation ──
    results = []
    print(f"\n[*] Validating {len(csv_devices)} device(s)...\n")
    status_icons = {
        DeviceResult.PASS: "✓",
        DeviceResult.FAIL: "✗",
        DeviceResult.WARN: "△",
        DeviceResult.NA:   "─",
    }

    for idx, csv_device in enumerate(csv_devices, start=1):
        hostname = csv_device["hostname"]
        print(f"  [{idx:>3}/{len(csv_devices)}]  {hostname}  (System IP: {csv_device['system_ip']})")

        try:
            result = validate_device(client, csv_device, all_devices, vedge_devices)
        except Exception as e:
            result = DeviceResult(
                csv_device["hostname"],
                csv_device["serial_number"],
                csv_device["system_ip"],
            )
            result.set_error(f"Unexpected error: {e}")
            _fill_na(result, "Error during validation")

        for check_name, chk in result.checks.items():
            icon = status_icons.get(chk["status"], "?")
            print(f"           {icon}  {check_name}: {chk['value']}")

        print(f"         {'─'*44}")
        print(f"           Overall result: {result.overall_status}\n")
        results.append(result)

    # ── Logout ──
    client.logout()

    # ── Print summary ──
    passed = sum(1 for r in results if r.overall_status == DeviceResult.PASS)
    failed = sum(1 for r in results if r.overall_status == DeviceResult.FAIL)
    warned = sum(1 for r in results if r.overall_status == DeviceResult.WARN)

    print("=" * 65)
    print("  Staging Validation Complete")
    print(f"  Total devices : {len(results)}")
    print(f"  PASS          : {passed}")
    print(f"  FAIL          : {failed}")
    print(f"  WARN          : {warned}")
    print("=" * 65)

    # ── Generate HTML report ──
    generate_html_report(results, args.output)


if __name__ == "__main__":
    main()
