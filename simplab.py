#!/usr/bin/env python3
"""
Simplilearn CloudLabs Credential Extractor (requests-only, no Selenium)
=======================================================================
Automates: Login → Discover Lab → LTI Launch → Extract Cloud Credentials

Requirements:
    pip install requests

Usage:
    python simplilearn_cloudlabs.py --email your@email.com --password 'yourpass'
    python simplilearn_cloudlabs.py --email your@email.com --password 'yourpass' --eid 2765
    python simplilearn_cloudlabs.py --odl-guid XXX --attendee-guid YYY   # skip login

Environment variables (alternative to CLI args):
    export SIMPLILEARN_EMAIL="your@email.com"
    export SIMPLILEARN_PASSWORD="yourpass"
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
from base64 import b64encode, b64decode
from urllib.parse import quote, urlencode, urlparse, parse_qs, urljoin

import requests

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
SIMPLILEARN_LOGIN_URL = "https://accountsv2.simplilearn.com/auth/login"
SIMPLILEARN_LMS_BASE = "https://lms.simplilearn.com"
LTI_LAUNCH_BASE = "https://lti.cloudlabs.ai"
CLOUDLABS_API_BASE = "https://api.cloudlabs.ai/api"
CLOUDLABS_MANAGE = "https://manage.cloudlabs.ai"

DEFAULT_EID = "2765"  # AWS Solutions Architect course
CACHE_DIR = os.path.expanduser("~/.cache/cloudlabs")
SESSION_FILE = os.path.join(CACHE_DIR, "session.json")

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
)


# ──────────────────────────────────────────────
# OAuth 1.0 HMAC-SHA1 Signing (LTI 1.0 standard)
# ──────────────────────────────────────────────
def percent_encode(s):
    """RFC 5849 percent-encoding."""
    return quote(str(s), safe="")


def generate_oauth_signature(method, url, params, consumer_secret):
    """
    Generate OAuth 1.0 HMAC-SHA1 signature for LTI launch.
    
    `params` must be a list of (key, value) tuples to preserve duplicates
    (e.g. resource_link_id appearing in both URL query and POST body).
    Key = consumer_secret + "&" (no token secret in LTI 1.0).
    """
    if isinstance(params, dict):
        param_list = list(params.items())
    else:
        param_list = list(params)

    # Sort by key first, then by value (per RFC 5849 §3.4.1.3.2)
    sorted_params = sorted(param_list, key=lambda x: (x[0], x[1]))
    param_string = "&".join(f"{percent_encode(k)}={percent_encode(v)}" for k, v in sorted_params)
    base_string = "&".join([method.upper(), percent_encode(url), percent_encode(param_string)])
    signing_key = f"{percent_encode(consumer_secret)}&"
    sig = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
    return b64encode(sig).decode()


def decode_jwt_payload(token):
    """Decode the payload of a JWT (no verification)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(b64decode(payload))
    except Exception:
        return {}


# ──────────────────────────────────────────────
# GUID Extraction Helpers
# ──────────────────────────────────────────────
GUID_RE = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'


def extract_guids_from_text(text):
    """Search HTML/JS/URL text for ODL and Attendee GUIDs."""
    guids = {"odl_guid": None, "attendee_guid": None}

    patterns = [
        (r'OnDemandLab/(' + GUID_RE + r')', "odl"),
        (r'LabViewDetails/(' + GUID_RE + r')/(' + GUID_RE + r')', "both"),
        (r'GetMultiCloudAttendeeTestDrive/(' + GUID_RE + r')', "attendee"),
        (r'GetMultiCloudLabViewDetails/(' + GUID_RE + r')/(' + GUID_RE + r')', "both"),
        (r'InitiateMulticloudDeployment/(' + GUID_RE + r')', None),  # internal ID, skip
        (r'(?:odlId|eventUniqueName|uniqueName)["\s:=]+["\']?(' + GUID_RE + r')', "odl"),
        (r'(?:attendeeId|attendeeGuid)["\s:=]+["\']?(' + GUID_RE + r')', "attendee"),
        (r'#/odl/(' + GUID_RE + r')/(' + GUID_RE + r')', "both"),
        (r'labguide/(' + GUID_RE + r')/(' + GUID_RE + r')', "both"),
    ]

    for pattern, kind in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            groups = match.groups()
            if kind == "both" and len(groups) >= 2:
                guids["odl_guid"] = guids["odl_guid"] or groups[0]
                guids["attendee_guid"] = guids["attendee_guid"] or groups[1]
            elif kind == "odl" and groups:
                guids["odl_guid"] = guids["odl_guid"] or groups[0]
            elif kind == "attendee" and groups:
                guids["attendee_guid"] = guids["attendee_guid"] or groups[0]

    # Also check URL query/fragment params
    for param_name, guid_key in [
        ("odlId", "odl_guid"), ("eventId", "odl_guid"), ("odlguid", "odl_guid"),
        ("attendeeId", "attendee_guid"), ("attendeeguid", "attendee_guid"),
    ]:
        match = re.search(rf'{param_name}=({GUID_RE})', text, re.IGNORECASE)
        if match:
            guids[guid_key] = guids[guid_key] or match.group(1)

    return guids


# ──────────────────────────────────────────────
# Simplilearn Session
# ──────────────────────────────────────────────
class SimplilearnSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.jwt_token = None
        self.user_name = None
        self.user_email = None
        self.user_id = None

    def login(self, email, password):
        """Step 1: POST /auth/login → get _sljt JWT cookie."""
        print(f"[1/5] Logging into Simplilearn as {email}...")

        resp = self.session.post(
            SIMPLILEARN_LOGIN_URL,
            data={
                "email": email,
                "password": password,
                "redirect_url": "https://lms.simplilearn.com",
                "calendar_url": "",
                "domainGid": "",
                "isB2BAndB2C": "",
                "domainUrl": "",
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://accountsv2.simplilearn.com",
            },
            allow_redirects=True,
            timeout=30,
        )

        # Extract _sljt cookie
        sljt = None
        for cookie in self.session.cookies:
            if cookie.name == "_sljt":
                sljt = cookie.value
                break

        if not sljt:
            print("[!] Login failed — no _sljt cookie received.")
            print(f"    Final URL: {resp.url}")
            return False

        self.jwt_token = sljt
        self.user_email = email

        # Decode JWT to extract user info
        jwt_data = decode_jwt_payload(sljt).get("data", {})
        self.user_name = jwt_data.get("name", email)
        self.user_id = ""  # Will be extracted from LMS page

        print(f"[+] Login successful! Welcome, {self.user_name}")

        # Extract numeric user_id from the LMS page
        self._extract_numeric_user_id()

        return True

    def _extract_numeric_user_id(self):
        """
        Fetch the LMS page and extract the numeric user ID.
        The Simplilearn frontend embeds it in JS/HTML and uses it for LTI launches.
        """
        try:
            resp = self.session.get(f"{SIMPLILEARN_LMS_BASE}/", timeout=15)
            html = resp.text

            # Common patterns where Simplilearn embeds the user ID
            patterns = [
                r'"user_id"\s*:\s*"?(\d{5,10})"?',
                r"'user_id'\s*:\s*'?(\d{5,10})'?",
                r'"userId"\s*:\s*"?(\d{5,10})"?',
                r"userId\s*[:=]\s*['\"]?(\d{5,10})",
                r"user_id\s*[:=]\s*['\"]?(\d{5,10})",
                r'"uid"\s*:\s*"?(\d{5,10})"?',
                r'"id"\s*:\s*(\d{5,10})\b',
                r'data-user-id="(\d{5,10})"',
                r'data-userid="(\d{5,10})"',
            ]

            for pattern in patterns:
                match = re.search(pattern, html)
                if match:
                    self.user_id = match.group(1)
                    print(f"    Numeric user_id: {self.user_id}")
                    return

            # Try fetching the workshop list API which may return user info
            try:
                resp2 = self.session.post(
                    f"{SIMPLILEARN_LMS_BASE}/user/lvcpass/get-active-session-count",
                    headers={"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"},
                    timeout=10,
                )
                for pattern in patterns:
                    match = re.search(pattern, resp2.text)
                    if match:
                        self.user_id = match.group(1)
                        print(f"    Numeric user_id: {self.user_id}")
                        return
            except Exception:
                pass

            print("    [!] Could not extract numeric user_id (may still work without it)")

        except Exception as e:
            print(f"    [!] user_id extraction failed: {e}")

    def get_lab_list(self, eid):
        """Step 2: POST /user/cloudlab/get-lab-list → discover labs."""
        print(f"\n[2/5] Fetching lab list for course EID={eid}...")

        resp = self.session.post(
            f"{SIMPLILEARN_LMS_BASE}/user/cloudlab/get-lab-list",
            data={"eid": eid},
            headers={
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": SIMPLILEARN_LMS_BASE,
                "Referer": f"{SIMPLILEARN_LMS_BASE}/courses/{eid}/",
            },
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()

        if result.get("status") != "success" or not result.get("data"):
            print(f"[!] No labs found for EID={eid}")
            return None

        labs = result["data"]
        print(f"[+] Found {len(labs)} lab(s):")
        for lab in labs:
            print(f"    • [{lab['id']}] {lab['labDisplayName']}")

        return labs

    def access_lab(self, lab, eid):
        """Step 3: POST /user/cloudlab/access-lab/ → get LTI config + OAuth keys."""
        lab_id = lab["id"]
        print(f"\n[3/5] Requesting lab access (lab ID={lab_id})...")

        resp = self.session.post(
            f"{SIMPLILEARN_LMS_BASE}/user/cloudlab/access-lab/",
            data={
                "elearningId": eid,
                "source": lab["source"],
                "labId": lab_id,
                "mechanism": lab["mechanism"],
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": SIMPLILEARN_LMS_BASE,
                "Referer": f"{SIMPLILEARN_LMS_BASE}/courses/{eid}/",
            },
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()

        if result.get("status") != "Success" or not result.get("data"):
            print(f"[!] Failed to get lab access.")
            return None

        data = result["data"][0]
        lab_config = json.loads(data["labConfig"])

        print(f"[+] Lab access granted!")
        print(f"    Launch URL: {data['launchUrl']}")
        print(f"    Expiry:     {data.get('expiryTimestamp', 'N/A')}")

        return {
            "consumer_key": lab_config["consumerKey"],
            "secret_key": lab_config["secretKey"],
            "lti_config": json.loads(data["ltiConfig"]),
            "launch_url": data["launchUrl"],
            "lab_display_name": data.get("labDisplayName", ""),
            "resource_link_id": str(lab_id),
            "expiry_timestamp": data.get("expiryTimestamp", ""),
            "user_lab_tags": data.get("userLabTags", "{}"),
        }

    def lti_launch(self, access_info, debug=False):
        """
        Step 4: POST LTI Launch with OAuth 1.0 HMAC-SHA1 signature.
        This hands off your identity from Simplilearn to CloudLabs.
        """
        print(f"\n[4/5] Performing LTI Launch (OAuth 1.0 HMAC-SHA1)...")

        consumer_key = access_info["consumer_key"]
        secret_key = access_info["secret_key"]
        launch_url = access_info["launch_url"]

        # Base URL for signing AND posting (browser strips query params)
        # Burp shows: POST /Provider/Launch HTTP/1.1 (NO ?resource_link_id=452)
        # The resource_link_id goes into POST body only
        base_url = launch_url.split("?")[0]

        # Merge any query params from launch_url into LTI params
        # (e.g., resource_link_id=452 moves from URL to POST body)
        parsed = urlparse(launch_url)
        url_params = {}
        for k, v_list in parse_qs(parsed.query).items():
            url_params[k] = v_list[0]

        # Build LTI params (matching the exact Burp capture structure)
        lti_params = {
            "context_id": "",
            "context_label": "",
            "context_title": "",
            "delete_frequency": access_info.get("expiry_timestamp", ""),
            "lis_person_contact_email_primary": self.user_email,
            "lis_person_name_family": self.user_name or "",
            "lis_person_name_full": self.user_name or "",
            "lis_person_name_given": self.user_name or "",
            "lti_message_type": "basic-lti-launch-request",
            "lti_version": "LTI-1p0",
            "oauth_callback": "about:blank",
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": uuid.uuid4().hex[:23],
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_version": "1.0",
            "resource_link_description": access_info["lab_display_name"],
            "resource_link_id": url_params.get("resource_link_id", access_info["resource_link_id"]),
            "resource_link_title": access_info["lab_display_name"],
            "roles": "Learner",
            "tool_consumer_info_product_family_code": "simplilearn",
            "tool_consumer_instance_description": "",
            "tool_consumer_instance_guid": "",
            "user_id": self.user_id or "",
            "userlab_tags": access_info.get("user_lab_tags", "{}"),
        }

        # Generate OAuth signature — all POST body params, NO URL query duplication
        signature = generate_oauth_signature("POST", base_url, lti_params, secret_key)
        lti_params["oauth_signature"] = signature

        print(f"    Nonce:     {lti_params['oauth_nonce']}")
        print(f"    Timestamp: {lti_params['oauth_timestamp']}")
        print(f"    Signature: {signature[:24]}...")
        print(f"    Base URL:  {base_url}")
        print(f"    user_id:   '{lti_params['user_id']}'")

        # Save debug info only if --debug is set
        if debug:
            sig_params_sorted = sorted(lti_params.items(), key=lambda x: (x[0], x[1]))
            param_str = "&".join(f"{percent_encode(k)}={percent_encode(v)}" for k, v in sig_params_sorted if k != "oauth_signature")
            base_str = "&".join(["POST", percent_encode(base_url), percent_encode(param_str)])
            os.makedirs(CACHE_DIR, exist_ok=True)
            oauth_debug = os.path.join(CACHE_DIR, "oauth_debug.txt")
            with open(oauth_debug, "w") as f:
                f.write(f"Base URL: {base_url}\n")
                f.write(f"Secret Key: {secret_key}\n")
                f.write(f"Signing Key: {percent_encode(secret_key)}&\n\n")
                f.write(f"Parameters (sorted):\n")
                for k, v in sig_params_sorted:
                    if k != "oauth_signature":
                        f.write(f"  {k} = {v}\n")
                f.write(f"\nParam string:\n{param_str}\n")
                f.write(f"\nBase string:\n{base_str}\n")
                f.write(f"\nSignature: {signature}\n")
            print(f"    (Debug saved to {oauth_debug})")

        # POST to base URL (no query string!) — matches browser behavior
        resp = self.session.post(
            base_url,
            data=lti_params,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": SIMPLILEARN_LMS_BASE,
                "Referer": f"{SIMPLILEARN_LMS_BASE}/",
            },
            allow_redirects=False,  # Handle redirects manually to inspect each hop
        )

        print(f"    Response:  {resp.status_code}")

        guids = {"odl_guid": None, "attendee_guid": None}
        all_text = ""

        # Follow redirect chain manually
        max_redirects = 10
        current_resp = resp

        for i in range(max_redirects):
            # Collect text from every response
            all_text += f"\n--- Response {resp.status_code} ---\n"
            all_text += f"URL: {current_resp.url}\n"
            all_text += f"Headers: {dict(current_resp.headers)}\n"
            all_text += current_resp.text + "\n"

            if current_resp.status_code in (301, 302, 303, 307, 308):
                location = current_resp.headers.get("Location", "")
                all_text += f"Redirect: {location}\n"
                print(f"    → Redirect [{current_resp.status_code}]: {location[:100]}")

                # Make it absolute if relative
                if not location.startswith("http"):
                    location = urljoin(current_resp.url, location)

                current_resp = self.session.get(location, allow_redirects=False)
            else:
                break

        # Final response
        all_text += f"\n--- Final ({current_resp.status_code}) ---\n"
        all_text += f"URL: {current_resp.url}\n"
        all_text += current_resp.text

        # Search ALL collected text for GUIDs
        guids = extract_guids_from_text(all_text)

        # Also check the final URL itself
        final_url_guids = extract_guids_from_text(current_resp.url)
        guids["odl_guid"] = guids["odl_guid"] or final_url_guids["odl_guid"]
        guids["attendee_guid"] = guids["attendee_guid"] or final_url_guids["attendee_guid"]

        # Check all cookies for GUIDs
        for cookie in self.session.cookies:
            cookie_guids = extract_guids_from_text(cookie.value)
            guids["odl_guid"] = guids["odl_guid"] or cookie_guids["odl_guid"]
            guids["attendee_guid"] = guids["attendee_guid"] or cookie_guids["attendee_guid"]

        if guids["odl_guid"] and guids["attendee_guid"]:
            print(f"\n[+] GUIDs captured!")
            print(f"    ODL:      {guids['odl_guid']}")
            print(f"    Attendee: {guids['attendee_guid']}")
        else:
            print(f"\n[!] Could not extract both GUIDs automatically.")
            print(f"    ODL:      {guids['odl_guid'] or 'NOT FOUND'}")
            print(f"    Attendee: {guids['attendee_guid'] or 'NOT FOUND'}")

            # Save debug output
            debug_file = os.path.join(CACHE_DIR, "lti_debug.txt")
            with open(debug_file, "w") as f:
                f.write(all_text)
            print(f"    Full response chain saved to {debug_file}")
            print(f"    Search this file for GUIDs manually, then re-run with --odl-guid / --attendee-guid")

        return guids


# ──────────────────────────────────────────────
# CloudLabs API Client
# ──────────────────────────────────────────────
class CloudLabsClient:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "Accept": "application/json, text/plain, */*",
            "User-Agent": USER_AGENT,
            "Origin": CLOUDLABS_MANAGE,
            "Referer": f"{CLOUDLABS_MANAGE}/",
        })

    def get_odl_config(self, odl_guid):
        url = f"{CLOUDLABS_API_BASE}/AttendeeTestDrive/OnDemandLab/{odl_guid}/en-us"
        return self.session.get(url, timeout=30).json()

    def get_attendee_status(self, attendee_guid):
        url = f"{CLOUDLABS_API_BASE}/AttendeeTestDrive/GetMultiCloudAttendeeTestDrive/{attendee_guid}"
        return self.session.get(url, timeout=30).json()

    def initiate_deployment(self, internal_id):
        url = f"{CLOUDLABS_API_BASE}/AttendeeTestDrive/InitiateMulticloudDeployment/{internal_id}"
        return self.session.get(url, timeout=60).json()

    def get_lab_credentials(self, odl_guid, attendee_guid):
        url = f"{CLOUDLABS_API_BASE}/AttendeeTestDrive/GetMultiCloudLabViewDetails/{odl_guid}/{attendee_guid}"
        return self.session.get(url, timeout=30).json()

    def wait_for_deployment(self, attendee_guid, timeout=300, interval=10):
        """Poll until deployment succeeds."""
        print(f"\n[*] Waiting for deployment (timeout={timeout}s)...")
        start = time.time()

        while time.time() - start < timeout:
            info = self.get_attendee_status(attendee_guid)
            status = info.get("DeploymentStatus", "Unknown")
            user_status = info.get("UserStatus", 0)
            elapsed = int(time.time() - start)

            print(f"    [{elapsed:3d}s] Deployment={status}, UserStatus={user_status}")

            if status.upper() == "SUCCEEDED":
                print("[+] Deployment ready!")
                return True
            elif status.upper() in ("FAILED", "ERROR", "CANCELLED"):
                print(f"[!] Deployment failed: {status}")
                return False

            time.sleep(interval)

        print("[!] Timed out waiting for deployment.")
        return False

    def stop_lab(self, odl_guid, attendee_guid):
        """Stop a running lab using the InternalId from lab details."""
        print(f"[*] Fetching lab details for InternalId...")
        details = self.get_lab_credentials(odl_guid, attendee_guid)
        internal_id = details.get("InternalId")
        status = details.get("Status")

        if not internal_id:
            print("[!] Could not get InternalId from lab details.")
            return False

        print(f"    Status:     {status}")
        print(f"    InternalId: {internal_id}")

        print(f"[*] Sending CompleteTestDrive request...")
        url = f"{CLOUDLABS_API_BASE}/AttendeeTestDrive/CompleteTestDrive/{internal_id}"
        resp = self.session.get(url, timeout=30)

        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("Status") == "Success":
                    print(f"[+] Lab stopped successfully!")
                    return True
                else:
                    print(f"[!] Response: {data.get('ErrorMessage', resp.text[:300])}")
                    return False
            except Exception:
                print(f"[+] Lab stopped (status {resp.status_code}).")
                return True
        else:
            print(f"[!] Stop request returned {resp.status_code}: {resp.text[:300]}")
            return False


# ──────────────────────────────────────────────
# Credential Display
# ──────────────────────────────────────────────
def parse_and_display(lab_details, lab_info=None):
    """Parse credentials from API response and display them."""
    allocations = lab_details.get("AllocatedTestDriveViewModalDetails", [])
    if not allocations:
        print("[!] No credentials found in response.")
        return []

    creds = []
    platform_map = {1: "Azure", 2: "AWS", 3: "GCP"}

    print("\n" + "=" * 62)
    print("   ☁️  CLOUD LAB CREDENTIALS")
    print("=" * 62)

    if lab_info:
        title = lab_info.get("Title") or lab_info.get("CustomTitle") or "N/A"
        print(f"\n   Lab:      {title}")
        print(f"   Partner:  {lab_info.get('PartnerName', 'N/A')}")
        print(f"   Duration: {lab_info.get('Duration', 'N/A')} min")

    started = lab_details.get("StartTime", "N/A")
    duration = lab_details.get("Duration", "N/A")
    print(f"   Started:  {started}")
    print(f"   Duration: {duration} min")

    for i, alloc in enumerate(allocations, 1):
        pid = alloc.get("CloudPlatformId")
        platform = platform_map.get(pid, f"Unknown({pid})")

        print(f"\n{'─' * 62}")
        print(f"   [{i}] {platform}  —  {alloc.get('CurrentStatus', 'N/A')}")
        print(f"{'─' * 62}")

        cred = {"platform": platform}

        if pid == 2:  # AWS
            acct = alloc.get("SubscriptionGuid", "")
            ak = alloc.get("AADSPAppId", "")
            sk = alloc.get("AADSPAppKey", "")
            region = alloc.get("ResourceGroupRegion", "")
            user = alloc.get("AADEmail", "")
            pw = alloc.get("TempPassword", "")

            cred.update(dict(
                iam_user=user, password=pw, account_id=acct,
                access_key_id=ak, secret_access_key=sk, region=region,
            ))

            print(f"   IAM User:          {user}")
            print(f"   Password:          {pw}")
            print(f"   Account ID:        {acct}")
            print(f"   Access Key ID:     {ak}")
            print(f"   Secret Access Key: {sk}")
            print(f"   Region:            {region}")
            print(f"   Console:           https://{acct}.signin.aws.amazon.com/console")
            print()
            print(f"   ┌─── Export (paste into terminal) ─────────────")
            print(f"   │ export AWS_ACCESS_KEY_ID=\"{ak}\"")
            print(f"   │ export AWS_SECRET_ACCESS_KEY=\"{sk}\"")
            print(f"   │ export AWS_DEFAULT_REGION=\"{region}\"")
            print(f"   └──────────────────────────────────────────────")

        elif pid == 1:  # Azure
            user = alloc.get("AADEmail", "")
            pw = alloc.get("TempPassword", "")
            tenant = alloc.get("TenantId", "")
            sub_id = alloc.get("SubscriptionGuid", "")

            cred.update(dict(
                username=user, password=pw, tenant_id=tenant,
                subscription_id=sub_id, resource_group=alloc.get("ResourceGroupName", ""),
            ))

            print(f"   Username:       {user}")
            print(f"   Password:       {pw}")
            print(f"   Tenant:         {alloc.get('TenantDomainName', 'N/A')}")
            print(f"   Subscription:   {alloc.get('SubscriptionFriendlyName', '')} ({sub_id})")
            print(f"   Resource Group: {alloc.get('ResourceGroupName', 'N/A')}")
            print(f"   Portal:         https://portal.azure.com")

            sp_id = alloc.get("AADSPAppId")
            sp_key = alloc.get("AADSPAppKey")
            if sp_id and sp_key:
                print()
                print(f"   ┌─── az login (Service Principal) ────────────")
                print(f"   │ az login --service-principal \\")
                print(f"   │   -u \"{sp_id}\" \\")
                print(f"   │   -p \"{sp_key}\" \\")
                print(f"   │   --tenant \"{tenant}\"")
                print(f"   └──────────────────────────────────────────────")

        print(f"\n   Deployment: {alloc.get('DeploymentName', 'N/A')}")
        creds.append(cred)

    print(f"\n{'=' * 62}\n")
    return creds


# ──────────────────────────────────────────────
# Session Persistence
# ──────────────────────────────────────────────
def save_session(odl_guid, attendee_guid, lab_details, creds):
    """Save session info so --stop-lab can work without GUIDs."""
    session = {
        "odl_guid": odl_guid,
        "attendee_guid": attendee_guid,
        "internal_id": lab_details.get("InternalId"),
        "start_time": lab_details.get("StartTime"),
        "duration": lab_details.get("Duration"),
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "credentials": creds,
    }
    with open(SESSION_FILE, "w") as f:
        json.dump(session, f, indent=2)
    print(f"[+] Session saved to {SESSION_FILE}")


def load_session():
    """Load saved session for --stop-lab."""
    if not os.path.exists(SESSION_FILE):
        return None
    try:
        with open(SESSION_FILE) as f:
            session = json.load(f)
        print(f"[+] Loaded session from {SESSION_FILE}")
        print(f"    ODL:      {session.get('odl_guid')}")
        print(f"    Attendee: {session.get('attendee_guid')}")
        print(f"    Started:  {session.get('start_time', 'N/A')}")
        return session
    except Exception as e:
        print(f"[!] Failed to load session: {e}")
        return None


def clear_session():
    """Remove session file after lab is stopped."""
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        print(f"[+] Session file removed.")


CONFIG_FILE = os.path.join(CACHE_DIR, "config.json")

def load_config():
    """Load saved config (email, password, eid) from ~/.cache/cloudlabs/config.json."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(email, password, eid=None):
    """Save credentials to config file for future runs."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    config = load_config()
    config["email"] = email
    config["password"] = password
    if eid:
        config["eid"] = eid
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)  # owner-only read/write
    print(f"[+] Credentials saved to {CONFIG_FILE}")


# ──────────────────────────────────────────────
# AWS CLI Configuration
# ──────────────────────────────────────────────
def configure_aws(creds, profile="default", region_override=None):
    """Write AWS credentials to ~/.aws/credentials and ~/.aws/config."""
    # Find the first AWS credential
    aws_cred = None
    for c in creds:
        if c.get("platform") == "AWS":
            aws_cred = c
            break

    if not aws_cred:
        print("[!] No AWS credentials found to configure.")
        return False

    aws_dir = os.path.expanduser("~/.aws")
    os.makedirs(aws_dir, exist_ok=True)

    creds_file = os.path.join(aws_dir, "credentials")
    config_file = os.path.join(aws_dir, "config")

    ak = aws_cred.get("access_key_id", "")
    sk = aws_cred.get("secret_access_key", "")
    region = region_override or aws_cred.get("region", "us-east-1")

    # Update credentials file
    _update_ini_profile(creds_file, profile, {
        "aws_access_key_id": ak,
        "aws_secret_access_key": sk,
    })

    # Update config file
    config_section = f"profile {profile}" if profile != "default" else "default"
    _update_ini_profile(config_file, config_section, {
        "region": region,
        "output": "json",
    })

    print(f"\n[+] AWS CLI configured!")
    print(f"    Profile:    {profile}")
    print(f"    Region:     {region}")
    print(f"    Creds file: {creds_file}")
    print(f"    Config file: {config_file}")
    print(f"\n    Usage:")
    print(f"    aws sts get-caller-identity --profile {profile}")
    print(f"    export AWS_PROFILE={profile}")
    return True


def _update_ini_profile(filepath, profile, values):
    """Update or add a profile section in an INI file (preserves other profiles)."""
    lines = []
    if os.path.exists(filepath):
        with open(filepath) as f:
            lines = f.readlines()

    # Find and remove existing profile section
    new_lines = []
    in_target = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_target = (stripped[1:-1] == profile)
            if not in_target:
                new_lines.append(line)
        elif not in_target:
            new_lines.append(line)

    # Append the profile
    if new_lines and not new_lines[-1].endswith("\n"):
        new_lines.append("\n")
    new_lines.append(f"[{profile}]\n")
    for k, v in values.items():
        new_lines.append(f"{k} = {v}\n")
    new_lines.append("\n")

    with open(filepath, "w") as f:
        f.writelines(new_lines)


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Simplilearn CloudLabs Credential Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # First run — save credentials for future use
  python %(prog)s --email user@example.com --password 'P@ss' --save-creds

  # Fetch credentials (uses saved email/password)
  python %(prog)s

  # Fetch + configure AWS CLI (default profile)
  python %(prog)s --configure

  # Fetch + configure a named profile with region override
  python %(prog)s --configure mylab --region ap-south-1

  # Stop the running lab (uses saved session)
  python %(prog)s --stop-lab

  # Direct API (skip login)
  python %(prog)s --odl-guid 3f8790c7-... --attendee-guid 314bfefb-...
        """
    )

    # Load config file for defaults (CLI args > env vars > config file)
    config = load_config()
    parser.add_argument("--email", default=os.environ.get("SIMPLILEARN_EMAIL", config.get("email")))
    parser.add_argument("--password", default=os.environ.get("SIMPLILEARN_PASSWORD", config.get("password")))
    parser.add_argument("--eid", default=os.environ.get("SIMPLILEARN_EID", config.get("eid", DEFAULT_EID)),
                        help=f"Course elearning ID (default: {DEFAULT_EID})")
    parser.add_argument("--save-creds", action="store_true",
                        help="Save --email and --password to config file for future runs")
    parser.add_argument("--lab-index", type=int, default=0,
                        help="Which lab if multiple found (default: 0)")
    parser.add_argument("--odl-guid", help="CloudLabs ODL GUID (skip login)")
    parser.add_argument("--attendee-guid", help="CloudLabs Attendee GUID (skip login)")
    parser.add_argument("--user-id", help="Simplilearn numeric user ID (for LTI launch, optional)")
    parser.add_argument("--no-wait", action="store_true",
                        help="Don't wait for deployment")
    parser.add_argument("--stop-lab", action="store_true",
                        help="Stop/terminate the running lab instead of fetching credentials")
    parser.add_argument("--configure", nargs="?", const="default", default=None, metavar="PROFILE",
                        help="Configure AWS CLI with lab credentials (default profile: 'default')")
    parser.add_argument("--region", default=config.get("region"),
                        help="Override AWS region for --configure (also saved with --save-creds)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Deployment timeout seconds (default: 300)")
    parser.add_argument("--debug", action="store_true",
                        help="Save OAuth debug info to ~/.cache/cloudlabs/oauth_debug.txt")

    args = parser.parse_args()

    # ── Path 0: Load from session file (for --stop-lab without GUIDs) ──
    if args.stop_lab and not args.odl_guid and not args.attendee_guid and not (args.email and args.password):
        session = load_session()
        if session:
            odl_guid = session["odl_guid"]
            attendee_guid = session["attendee_guid"]
            cloudlabs = CloudLabsClient()
            print(f"\n[*] Stopping lab...")
            print(f"      ODL:      {odl_guid}")
            print(f"      Attendee: {attendee_guid}")
            cloudlabs.stop_lab(odl_guid, attendee_guid)
            clear_session()
            print("[+] Done!")
            sys.exit(0)
        else:
            print("[!] No saved session found. Provide --odl-guid + --attendee-guid, or --email + --password")
            sys.exit(1)

    # ── Path 1: Direct API ──
    if args.odl_guid and args.attendee_guid:
        print("[*] Using provided GUIDs (skipping login)...\n")
        odl_guid = args.odl_guid
        attendee_guid = args.attendee_guid
        cloudlabs = CloudLabsClient()

    # ── Path 2: Full automation ──
    elif args.email and args.password:
        # Save credentials if requested
        if args.save_creds:
            save_config(args.email, args.password, args.eid)
            # Also save region if provided
            if args.region:
                cfg = load_config()
                cfg["region"] = args.region
                with open(CONFIG_FILE, "w") as f:
                    json.dump(cfg, f, indent=2)

        sl = SimplilearnSession()

        if not sl.login(args.email, args.password):
            sys.exit(1)

        # Override user_id if provided via CLI
        if args.user_id:
            sl.user_id = args.user_id
            print(f"    Using provided user_id: {sl.user_id}")

        labs = sl.get_lab_list(args.eid)
        if not labs:
            sys.exit(1)

        access_info = sl.access_lab(labs[args.lab_index], args.eid)
        if not access_info:
            sys.exit(1)

        guids = sl.lti_launch(access_info, debug=args.debug)
        odl_guid = guids.get("odl_guid")
        attendee_guid = guids.get("attendee_guid")

        if not odl_guid or not attendee_guid:
            print("\n[!] Could not get both GUIDs. Check lti_debug.txt")
            print("    Then re-run with: --odl-guid XXX --attendee-guid YYY")
            sys.exit(1)

        cloudlabs = CloudLabsClient(session=sl.session)
    else:
        parser.print_help()
        print("\n[!] Need: --email + --password  OR  --odl-guid + --attendee-guid")
        print("    For --stop-lab: can also run standalone (reads saved session)")
        sys.exit(1)

    # ── Stop lab if requested ──
    if args.stop_lab:
        print(f"\n[*] Stopping lab...")
        print(f"      ODL:      {odl_guid}")
        print(f"      Attendee: {attendee_guid}")
        cloudlabs.stop_lab(odl_guid, attendee_guid)
        clear_session()
        print("[+] Done!")
        sys.exit(0)

    # ── Fetch Credentials ──
    print(f"\n[5/5] Fetching cloud credentials...")
    print(f"      ODL:      {odl_guid}")
    print(f"      Attendee: {attendee_guid}")

    lab_info = {}
    try:
        lab_info = cloudlabs.get_odl_config(odl_guid)
    except Exception as e:
        print(f"      [!] ODL config: {e}")

    # Wait for deployment if needed
    if not args.no_wait:
        try:
            info = cloudlabs.get_attendee_status(attendee_guid)
            status = info.get("DeploymentStatus", "Unknown")
            print(f"      Status: {status}")

            if status.upper() != "SUCCEEDED":
                internal_id = info.get("InternalId")
                if internal_id:
                    print(f"      Triggering deployment...")
                    try:
                        cloudlabs.initiate_deployment(internal_id)
                    except Exception:
                        pass
                cloudlabs.wait_for_deployment(attendee_guid, timeout=args.timeout)
        except Exception as e:
            print(f"      [!] Status check: {e}")

    # Get credentials
    try:
        lab_details = cloudlabs.get_lab_credentials(odl_guid, attendee_guid)
        creds = parse_and_display(lab_details, lab_info)

        if creds:

            # Save session for later --stop-lab
            save_session(odl_guid, attendee_guid, lab_details, creds)

            # Configure AWS CLI if requested
            if args.configure is not None:
                configure_aws(creds, profile=args.configure, region_override=args.region)

    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

    print("[+] Done!")


if __name__ == "__main__":
    main()
