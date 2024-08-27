#!/usr/bin/env python3

SCRIPT_VERSION = "1.1.0"

import os
import re
import sys
import logging
import argparse
import glob
import json
import hashlib
import requests
from requests.adapters import HTTPAdapter
import xml.etree.ElementTree as ET
from slugify import slugify

# Global variables
SUBDOMAIN = None
REGION = None
TOKEN = None
BASE_URL = None

logger = logging.getLogger(__name__)

def get_base_url(SUBDOMAIN, REGION):
# Kandji API Base URL
    if REGION in ["", "us"]:
        return f"https://{SUBDOMAIN}.api.kandji.io/api"
    elif REGION in ["eu"]:
        return f"https://{SUBDOMAIN}.api.eu.kandji.io/api"
    else:
        logger.error(f"Unsupported region {REGION}. Please update and try again.")
        sys.exit(1)

# Program Arguments
def program_arguments():
    """Return Program Arguments."""
    parser = argparse.ArgumentParser(
        prog = "git2kandji",
        description = "Git2Kandji - Sync Git Repo with Kandji.",
        allow_abbrev = False
    )
    parser.add_argument(
        "--subdomain",
        help = "Kandji subdomain (overrides global environment variable)"
    )
    parser.add_argument(
        "--region",
        choices = ["us", "eu"],
        help = "Kandji region (overrides global environment variable)"
    )
    parser.add_argument(
        "--token",
        help = "Kandji API token (overrides global environment variable)"
    )
    parser.add_argument(
        "--script-dir", 
        default = "scripts", 
        help = "directory containing script files (e.g. custom-scripts)"
        )
    parser.add_argument(
        "--script-ext", 
        default = "sh", 
        help = "space-separated list of file extensions to process (e.g., sh py zsh)"
        )
    parser.add_argument(
        "--profile-dir",
        default = "profiles",
        help = "directory containing profile files (e.g. custom-profiles)"
    )
    parser.add_argument(
        "--delete",
        action = "store_true",
        help = "Delete Kandji library items not present in local repository"
    )
    parser.add_argument(
        "--only-scripts",
        action = "store_true",
        help = "Only run the Kandji script portion"
    )
    parser.add_argument(
        "--only-profiles",
        action = "store_true",
        help = "Only run the Kandji profile portion"
    )
    parser.add_argument(
        "--download",
        action = "store_true",
        help = "Download existing scripts and profiles to local disk"
    )
    parser.add_argument(
        "--dryrun",
        action = "store_true",
        help = "Compares Kandji to local repository and outputs any changes to be made"
    )
    parser.add_argument(
        "--log-level",
        default = "INFO",
        choices = ["DEBUG", "INFO", "WARNING", "ERROR"],
        help = "Set the logging level"
    )
    parser.add_argument(
        "--version", action="version", 
        version = f'%(prog)s {SCRIPT_VERSION}', 
        help = "show this script's version"
        )

    return parser.parse_args()

# HTTP Error Handling
def http_errors(resp, resp_code, err_msg):
    """Handle HTTP errors."""
    # 400
    if resp_code == requests.codes["bad_request"]:
        logger.error(f"Bad request: {err_msg}\nResponse msg: {resp.text}")
    # 401
    elif resp_code == requests.codes["unauthorized"]:
        logger.error("Unauthorized access. Make sure that you have the required permissions to access this data.")
        logger.error(f"{err_msg}")
        sys.exit()
    # 403
    elif resp_code == requests.codes["forbidden"]:
        logger.error("Forbidden access. The API key may be invalid or missing.")
        logger.error(f"{err_msg}")
        sys.exit()
    # 404
    elif resp_code == requests.codes["not_found"]:
        logger.error("Not found. The resource cannot be found.")
        logger.error(f"Error: {err_msg}\nResponse msg: {resp.text}")
    # 429
    elif resp_code == requests.codes["too_many_requests"]:
        logger.error("Rate limit exceeded. Try again later.")
        logger.error(f"{err_msg}")
        sys.exit()
    # 500
    elif resp_code == requests.codes["internal_server_error"]:
        logger.error("Internal server error. The service is having a problem.")
        logger.error(f"{err_msg}")
        sys.exit()
    # 503
    elif resp_code == requests.codes["service_unavailable"]:
        logger.error("Service unavailable. Try again later.")
    else:
        logger.error("An unexpected error occurred.")
        logger.error(f"{err_msg}")
        sys.exit()

# Kandji API
def kandji_api(method, endpoint, headers, params=None, payload=None, files=None):
    """Make an API request and return data.

    method   - an HTTP Method (GET, POST, PATCH, DELETE).
    endpoint - the API URL endpoint to target.
    params   - optional parameters can be passed as a dict.
    payload  - optional payload is passed as a dict and used with PATCH and POST
               methods.
    Returns a JSON data object.
    """
    attom_adapter = HTTPAdapter(max_retries=3)
    session = requests.Session()
    session.mount(BASE_URL, attom_adapter)

    try:
        if files:
            response = session.request(
                method,
                BASE_URL + endpoint,
                data=payload,
                headers=headers,
                params=params,
                files=files,
                timeout=30,
        )
        else:
            response = session.request(
                method,
                BASE_URL + endpoint,
                data=payload,
                headers=headers,
                params=params,
                timeout=30,
        )

        # If a successful status code is returned (200 and 300 range)
        if response:
            try:
                data = response.json()
            except Exception:
                data = response.text

        # if the request is successful exceptions will not be raised
        response.raise_for_status()

    except requests.exceptions.RequestException as err:
        http_errors(resp=response, resp_code=response.status_code, err_msg=err)
        data = {"error": f"{response.status_code}", "api resp": f"{err}"}

    return data

# Find Local Items
def find_local_items(directory, extensions, item_type="script"):
    """Retrieve list of files given a folder path and the list of valid file extensions to look for."""
    audit_items = []
    remediation_items = []

    # Add a period before each extension if not already present
    extensions = [f".{ext}" if not ext.startswith('.') else ext for ext in extensions]

    logger.debug(f"Searching for {item_type}s with extensions {extensions} in directory {directory}")
    
    for file_type in extensions:
        pattern = f"{directory}/**/*{file_type}"
        logger.debug(f"Using pattern: {pattern}")
        found_items = glob.glob(pattern, recursive=True)
        
        for item in found_items:
            item_name = os.path.basename(item)
            if item_name.startswith('audit_') or not item_name.startswith('remediation_'):
                audit_items.append(item)
            elif item_name.startswith('remediation_'):
                remediation_items.append(item)

    total_items = len(audit_items) + len(remediation_items)
    
    if item_type == "script":
        logger.info(f"Total {item_type}s found: {total_items} (Audit: {len(audit_items)}, Remediation: {len(remediation_items)})")
    else:
        logger.info(f"Total {item_type}s found: {total_items}")
    
    return audit_items + remediation_items

def normalize_xml_content(xml_content):
    """Normalize XML content by removing specific key-value pairs at the root level only."""
    try:
        logger.debug("Starting XML normalization.")
        # Parse the XML content
        root = ET.fromstring(xml_content)
        logger.debug(f"Initial XML Content: {ET.tostring(root, encoding='unicode')}")

        # Define the tags that need to be removed at the root level
        tags_to_remove = ['PayloadDisplayName', 'PayloadIdentifier', 'PayloadUUID', 'PayloadScope']

        # Get the root <dict> element
        root_dict = root.find('dict')

        # Traverse the root <dict> and remove elements with matching tags, but not within PayloadContent
        if root_dict is not None:
            elements_to_remove = []
            for index, element in enumerate(root_dict):
                if element.tag == 'key' and element.text in tags_to_remove:
                    # Ensure we are not inside PayloadContent
                    if root_dict[index + 1].tag != 'array':
                        elements_to_remove.append((element, root_dict[index + 1]))

            # Remove the found elements and their corresponding values
            for key_element, value_element in elements_to_remove:
                logger.debug(f"Removing root-level key: {key_element.text} with value: {ET.tostring(value_element, encoding='unicode').strip()}")
                root_dict.remove(key_element)
                root_dict.remove(value_element)

        # Convert the XML tree back to a string
        normalized_content = ET.tostring(root, encoding='unicode')
        logger.debug(f"Normalized XML Content: {normalized_content}")
        return normalized_content.strip()
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML: {e}")
        return xml_content.strip()

def compare_items(new, old, is_xml=False):
    """Compare two items. Normalize XML content if applicable."""
    if is_xml:
        # Normalize XML content for profiles
        normalized_new = normalize_xml_content(new)
        normalized_old = normalize_xml_content(old)
    else:
        # No normalization needed for scripts
        normalized_new = new
        normalized_old = old

    # Calculate MD5 hashes
    md5_new = hashlib.md5(normalized_new.encode('utf-8')).hexdigest()
    md5_old = hashlib.md5(normalized_old.encode('utf-8')).hexdigest()

    logger.debug(f"Hash of New: {md5_new}")
    logger.debug(f"New Item Content: {normalized_new}")
    logger.debug(f"Hash of Old: {md5_old}")
    logger.debug(f"Old Item Content: {normalized_old}")

    return md5_new == md5_old

# List Custom Scripts
def list_custom_scripts():
    """List all Kandji Custom Scripts"""
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {TOKEN}'
    }

    # Set pagination parameters
    page_number = 1
    all_scripts = []

    while True:
        # Update parameters with pagination
        params = {
            'page': page_number
        }

        response = kandji_api(
            method="GET",
            endpoint="/v1/library/custom-scripts",
            headers=headers,
            params=params
        )

        logger.debug(f"API response for page {page_number}: {response}")

        for record in response["results"]:
            all_scripts.append(record)

        if response["next"] is None:
            if len(all_scripts) < 1:
                logger.warning("No scripts found")
            break

        page_number += 1

    return all_scripts

# Parse Script Metadata
def parse_script_metadata(audit_script_path, audit_script_content):
    """Parses metadata from the beginning of a script file."""

    # Default metadata
    metadata = {
        'name': os.path.basename(audit_script_path),
        'execution_frequency': 'once', # Options: once, every_15_min, every_day, no_enforcement
        'show_in_self_service': False,
        'self_service_category_id': None, # e.g. e6f6d5b4-0659-4b37-872c-5471115d453b
        'self_service_recommended': False,
        'active': True,
        'restart': False
    }

    for line in audit_script_content.splitlines():
        if line.startswith('# git2kandji-config:'):
            try:
                key, value = line[len('# git2kandji-config:'):].strip().split('=', 1)
                key = key.strip()
                value = value.strip()

                # Handle boolean values
                if value.lower() in ['true', 'false']:
                    value = value.lower() == 'true'
                # Handle None values
                elif value.lower() == 'none':
                    value = None
                # Handle string values (including UUIDs)
                else:
                    # If it's not a boolean or None, keep it as a string (potentially a UUID)
                    pass 

                metadata[key] = value
            except (ValueError, json.JSONDecodeError):
                logger.warning(f"Invalid metadata in script '{audit_script_path}': {line}")

    return metadata

# Create Custom Script
def create_custom_script(audit_script_path, remediation_script_path=None):
    """Create Kandji Custom Script"""

    # Read Audit Script Content
    audit_script_content = ""
    with open(audit_script_path, 'r') as file:
        audit_script_content = file.read()

    # Read Remediation Script Content
    remediation_script_content = ""
    if remediation_script_path:
        with open(remediation_script_path, 'r') as file:
            remediation_script_content = file.read()

    # Parse metadata
    metadata = parse_script_metadata(audit_script_path, audit_script_content)

    # Truncate the name if necessary
    metadata['name'] = truncate_name(metadata['name'])

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {TOKEN}'
    }

    payload = {
        'name': metadata['name'],
        'execution_frequency': metadata['execution_frequency'],
        'script': audit_script_content,
        'remediation_script': remediation_script_content,
        'show_in_self_service': metadata['show_in_self_service'],
        'active': metadata['active'],
        'restart': metadata['restart']
    }

    payload = json.dumps(payload)

    response = kandji_api(
        method = "POST",
        endpoint = "/v1/library/custom-scripts",
        headers=headers,
        payload=payload
    )
    return response

# Update Custom Script
def update_custom_script(library_item_id, audit_script_path, remediation_script_path=None):
    """Update Kandji Custom Script"""

    # Read Audit Script Content
    audit_script_content = ""
    with open(audit_script_path, 'r') as file:
        audit_script_content = file.read()

    # Read Remediation Script Content
    remediation_script_content = ""
    if remediation_script_path:
        with open(remediation_script_path, 'r') as file:
            remediation_script_content = file.read()

    # Parse metadata
    metadata = parse_script_metadata(audit_script_path, audit_script_content)

    # Truncate the name if necessary
    metadata['name'] = truncate_name(metadata['name'])

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {TOKEN}'
    }

    payload = {
        'name': metadata['name'],
        'execution_frequency': metadata['execution_frequency'],
        'script': audit_script_content,
        'remediation_script': remediation_script_content,
        'show_in_self_service': metadata['show_in_self_service'],
        'active': metadata['active'],
        'restart': metadata['restart']
    }

    payload = json.dumps(payload)

    response = kandji_api(
        method = "PATCH",
        endpoint = f"/v1/library/custom-scripts/{library_item_id}",
        headers=headers,
        payload=payload
    )
    return response

# Delete Custom Script
def delete_custom_script(library_item_id):
    """Delete Kandji Custom Script"""

    headers = {
        'Authorization': f'Bearer {TOKEN}'
    }

    response = kandji_api(
        method = "DELETE",
        endpoint = f"/v1/library/custom-scripts/{library_item_id}",
        headers=headers
    )
    return response

# List Custom Profiles
def list_custom_profiles():
    """List all Kandji Custom Profiles."""
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {TOKEN}'
    }

    # Set pagination parameters
    page_number = 1
    all_profiles = []

    while True:
        # Update parameters with pagination
        params = {
            'page': page_number
        }

        response = kandji_api(
            method="GET",
            endpoint="/v1/library/custom-profiles",
            headers=headers,
            params=params
        )

        logger.debug(f"API response for page {page_number}: {response}")

        for record in response["results"]:
            all_profiles.append(record)

        if response["next"] is None:
            if len(all_profiles) < 1:
                logger.warning("No profiles found")
            break

        page_number += 1

    return all_profiles

# Parse Profile Metadata
def parse_profile_metadata(profile_path, profile_content):
    """Parses metadata from the XML comments in a profile file."""

    # Default metadata
    metadata = {
        'name': os.path.basename(profile_path),
        'active': True,
    }

    # Regex to match XML comments
    comment_pattern = re.compile(r'<!--\s*git2kandji-config:\s*(.*?)\s*-->')

    for match in comment_pattern.findall(profile_content):
        try:
            key, value = match.split('=', 1)
            key = key.strip()
            value = value.strip()

            # Handle boolean values
            if value.lower() in ['true', 'false']:
                value = value.lower() == 'true'
            # Handle None values
            elif value.lower() == 'none':
                value = None
            # Handle string values (including UUIDs)
            else:
                # If it's not a boolean or None, keep it as a string (potentially a UUID)
                pass 

            metadata[key] = value
        except (ValueError, ET.ParseError):
            logger.warning(f"Invalid metadata in profile '{profile_path}': {match}")

    return metadata

# Create Custom Profile
def create_custom_profile(profile_path):
    """Create Kandji Custom Profile"""

    # Set Profile Name
    profile_name = os.path.basename(profile_path)
    
    # Read Profile Content
    with open(profile_path, 'r') as file:
        profile_content = file.read()

    # Parse Metadata
    metadata = parse_profile_metadata(profile_path, profile_content)

    # Truncate the name if necessary
    metadata['name'] = truncate_name(metadata['name'])

    # Profile Content
    files = {
            'file': (profile_name, open(profile_path, 'rb'), 'application/octet-stream')
    }

    headers = {
        'Authorization': f'Bearer {TOKEN}'
    }

    payload = {
        'name': metadata['name'],
        'active': metadata['active']
    }

    response = kandji_api(
        method = "POST",
        endpoint = "/v1/library/custom-profiles",
        headers = headers,
        payload = payload,
        files = files
    )
    return response

# Update Custom Profile
def update_custom_profile(library_item_id, profile_path):
    """Update Kandji Custom Profile"""

    # Profile Name
    profile_name = os.path.basename(profile_path)

    with open(profile_path, 'r') as file:
        profile_content = file.read()

    metadata = parse_profile_metadata(profile_path, profile_content)

    # Truncate the name if necessary
    metadata['name'] = truncate_name(metadata['name'])

    # Profile Content
    files = {
            'file': (profile_name, open(profile_path, 'rb'), 'application/octet-stream')
    }

    headers = {
        'Authorization': f'Bearer {TOKEN}'
    }

    payload = {
        'name': metadata['name'],
        'active': metadata['active']
    }

    response = kandji_api(
        method = "PATCH",
        endpoint = f"/v1/library/custom-profiles/{library_item_id}",
        headers = headers,
        payload = payload,
        files = files
    )
    return response

# Delete Custom Profile
def delete_custom_profile(library_item_id):
    """Delete Kandji Custom Profile"""

    headers = {
        'Authorization': f'Bearer {TOKEN}'
    }

    response = kandji_api(
        method = "DELETE",
        endpoint = f"/v1/library/custom-profiles/{library_item_id}",
        headers = headers
    )
    return response

# Sync Kandji Scripts
def sync_kandji_scripts(local_scripts, kandji_scripts, dryrun=False):
    kandji_script_dict = {script["name"]: script for script in kandji_scripts}

    # Group audit and remediation scripts
    grouped_scripts = {}
    for local_script in local_scripts:
        script_name = os.path.basename(local_script)
        if script_name.startswith("audit_"):
            base_name = script_name[len("audit_"):]
            grouped_scripts.setdefault(base_name, {})['audit'] = local_script
        elif script_name.startswith("remediation_"):
            base_name = script_name[len("remediation_"):]
            grouped_scripts.setdefault(base_name, {})['remediation'] = local_script
        else:
            # Assume scripts without a prefix are audit scripts
            base_name = script_name
            grouped_scripts.setdefault(base_name, {})['audit'] = local_script

    for base_name, scripts in grouped_scripts.items():
        audit_script = scripts.get('audit')
        remediation_script = scripts.get('remediation')

        # Parse metadata from the audit script (or remediation if audit is missing)
        metadata_script = audit_script

        metadata = {}
        with open(metadata_script, 'r') as f:
            metadata = parse_script_metadata(metadata_script, f.read())
        
        # Use the configured name or fallback to base_name
        configured_name = metadata['name'] or base_name

        # If there's a remediation script but no audit script, log a warning and skip the update
        if remediation_script and not audit_script:
            logger.warning(f"Remediation script '{remediation_script}' found without a matching audit script. No update will be made.")
            continue

        if configured_name in kandji_script_dict:
            kandji_script = kandji_script_dict[configured_name]
            audit_changed = False
            remediation_changed = False

            # Compare audit script
            if audit_script:
                with open(audit_script, 'r') as f:
                    local_audit_content = f.read()
                audit_changed = not compare_items(local_audit_content, kandji_script['script'], is_xml=False)

            # Compare remediation script or check if it has been deleted
            if remediation_script:
                with open(remediation_script, 'r') as f:
                    local_remediation_content = f.read()
                remediation_changed = not compare_items(local_remediation_content, kandji_script.get('remediation_script', ''), is_xml=False)
            elif 'remediation_script' in kandji_script and kandji_script.get('remediation_script', ''):
                # Remediation script exists in Kandji but not locally and needs to be removed
                logger.info(f"Remediation script for '{configured_name}' found in Kandji but not locally. It will be removed.")
                remediation_changed = True
                remediation_script = None  # Explicitly set to None to remove it

            # Only update if there are changes
            if audit_changed or remediation_changed:
                if dryrun:
                    logger.info(f"[DRY RUN] Would update Kandji Custom Script Library Item: {configured_name}")
                else:
                    logger.info(f"Updating Kandji Custom Script Library Item: {configured_name}")
                    update_custom_script(kandji_script["id"], audit_script, remediation_script)
            else:
                logger.info(f"No changes detected for Kandji Custom Script Library Item: {configured_name}")
        else:
            if dryrun:
                logger.info(f"[DRY RUN] Would create Kandji Custom Script Library Item: {configured_name}")
            else:
                logger.info(f"Creating Kandji Custom Script Library Item: {configured_name}")
                create_custom_script(audit_script, remediation_script)

# Sync Kandji Profiles
def sync_kandji_profiles(local_profiles, kandji_profiles, dryrun=False):
    kandji_profile_dict = {profile["name"]: profile for profile in kandji_profiles}

    for local_profile in local_profiles:
        profile_name = os.path.basename(local_profile)

        metadata = {}
        with open(local_profile, 'r') as f:
            metadata = parse_profile_metadata(local_profile, f.read())
        
        # Use the configured name or fallback to base_name
        configured_name = metadata['name'] or profile_name
        
        if configured_name in kandji_profile_dict:
            kandji_profile = kandji_profile_dict[configured_name]
            with open(local_profile, 'r') as f:
                local_content = f.read()
            kandji_content = kandji_profile.get('profile')            
            kandji_status = kandji_profile.get('active')

            metadata_changed = metadata['active'] != kandji_status

            if kandji_content:
                if not compare_items(local_content, kandji_content, is_xml=True) or metadata_changed:
                    if dryrun:
                        logger.info(f"[DRY RUN] Would update Kandji Custom Profile Library Item: {configured_name}")
                    else:
                        logger.info(f"Updating Kandji Custom Profile Library Item: {configured_name}")
                        update_custom_profile(kandji_profile["id"], local_profile)
                else:
                    logger.info(f"No changes detected for Kandji Custom Profile Library Item: {configured_name}")
            else:
                logger.warning(f"No content found for Kandji profile: {configured_name}")
        else:
            if dryrun:
                logger.info(f"[DRY RUN] Would create Kandji Custom Profile Library Item: {configured_name}")
            else:
                logger.info(f"Creating Kandji Custom Profile Library Item: {configured_name}")
                create_custom_profile(local_profile)

# Delete Kandji Items
def delete_items(kandji_items, local_items, delete_func, dryrun=False):
    # Create a set of local item names without prefixes
    local_names = set()
    for local_item in local_items:
        base_name = os.path.basename(local_item)
        if base_name.startswith("audit_"):
            local_names.add(base_name[len("audit_"):])
        elif base_name.startswith("remediation_"):
            local_names.add(base_name[len("remediation_"):])
        else:
            local_names.add(base_name)

    for item in kandji_items:
        item_name = item["name"]
        if item_name not in local_names:
            if dryrun:
                logger.info(f"[DRY RUN] Would delete Kandji item '{item_name}'")
            else:
                logger.info(f"Deleting Kandji item '{item_name}'")
                delete_func(item["id"])

# Download Script
def download_script(library_item_id, script_dir):
    """Download a script from Kandji and save it locally."""

    # Ensure the script directory exists
    os.makedirs(script_dir, exist_ok=True)

    headers = {
        'Authorization': f'Bearer {TOKEN}'
    }

    response = kandji_api(
        method="GET",
        endpoint=f"/v1/library/custom-scripts/{library_item_id}",
        headers=headers
    )

    script_name = response["name"]
    audit_content = response["script"]
    remediation_content = response.get("remediation_script", "")  # Handle missing remediation

    # Slugify script name for filenames
    slugified_name = slugify(script_name)

    # Save audit script with metadata config
    audit_file_path = os.path.join(script_dir, f"audit_{slugified_name}.sh")

    contains_config = "# git2kandji-config: " in audit_content

    with open(audit_file_path, 'w') as f:
        if contains_config:
            f.write(audit_content)
        else:
            # Check for shebang and add metadata config below it if present
            if audit_content.startswith("#!"):
                shebang, rest_of_content = audit_content.split('\n', 1)
                f.write(f"{shebang}\n\n# git2kandji-config: name = {script_name}\n\n{rest_of_content}")
            else:
                f.write(f"# git2kandji-config: name = {script_name}\n\n{audit_content}")

    # Save remediation script if it exists (with slugified name)
    if remediation_content:
        remediation_file_path = os.path.join(script_dir, f"remediation_{slugified_name}.sh")
        with open(remediation_file_path, 'w') as f:
            f.write(remediation_content)

# Download Profile
def download_profile(library_item_id, profile_dir):
    """Download a profile from Kandji and save it locally."""

    # Ensure the profile directory exists
    os.makedirs(profile_dir, exist_ok=True)

    headers = {
        'Authorization': f'Bearer {TOKEN}'
    }

    response = kandji_api(
        method="GET",
        endpoint=f"/v1/library/custom-profiles/{library_item_id}",
        headers=headers
    )

    profile_name = response["name"]
    profile_content = response["profile"]

    slugified_name = slugify(profile_name)

    # Check if the profile name is already included as a comment
    comment = f"<!-- git2kandji-config: name = {profile_name} -->"
    if comment not in profile_content:
        # Add the profile name as a comment at the beginning of the XML file after the XML declaration
        profile_content = profile_content.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{comment}")

    # Save profile
    profile_file_path = os.path.join(profile_dir, slugified_name + ".mobileconfig")
    with open(profile_file_path, 'w') as f:
        f.write(profile_content)

# Truncate Library Item Names if too long (Current limit is 50 characters)
def truncate_name(name, max_length=50):
    """Truncate the name to ensure it doesn't exceed the max length."""
    if len(name) > max_length:
        truncated_name = name[:max_length]
        logger.warning(f"Name '{name}' is too long and has been truncated to '{truncated_name}'")
        return truncated_name
    return name

# Main Logic
def main():
    """Run main logic."""
    global SUBDOMAIN, REGION, TOKEN, BASE_URL

     # Return Program Arguments
    args = program_arguments()

    # Set logging level based on argument
    logging_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=logging_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

    # Override global variables with command-line arguments if provided
    SUBDOMAIN = args.subdomain or os.getenv("INPUT_KANDJI_SUBDOMAIN")
    REGION = args.region or os.getenv("INPUT_KANDJI_REGION")
    TOKEN = args.token or os.getenv("INPUT_KANDJI_TOKEN")
    BASE_URL = get_base_url(SUBDOMAIN, REGION)

    # Handle script and profile directories and extensions
    script_dir = args.script_dir or os.getenv("INPUT_SCRIPT_DIR")
    script_ext = args.script_ext.split() or os.getenv("INPUT_SCRIPT_EXT").split()
    profile_dir = args.profile_dir or os.getenv("INPUT_PROFILE_DIR")
    profile_ext = ["mobileconfig"]

    # Handle dry run, delete, only scripts, and only profiles flags
    dryrun = args.dryrun or os.getenv("INPUT_DRYRUN", "false").lower() == "true"
    delete = args.delete or os.getenv("INPUT_DELETE", "false").lower() == "true"
    only_scripts = args.only_scripts or os.getenv("INPUT_ONLY_SCRIPTS", "false").lower() == "true"
    only_profiles = args.only_profiles or os.getenv("INPUT_ONLY_PROFILES", "false").lower() == "true"
    download = args.download or os.getenv("INPUT_DOWNLOAD", "false").lower() == "true"

    # Determine which portions to run
    if only_scripts:
        logger.info("Running Kandji script portion only.")
        local_scripts = find_local_items(script_dir, script_ext, item_type="script")
        kandji_scripts = list_custom_scripts()
        sync_kandji_scripts(local_scripts, kandji_scripts, dryrun)

        if delete:
            logger.info("Delete flag enabled. Comparing Kandji scripts with the local repo for potential deletions.")
            delete_items(kandji_scripts, local_scripts, delete_custom_script, dryrun)

        if download:
            logger.info("Download flag enabled. Downloading all scripts from Kandji.")

            # Download scripts
            kandji_scripts = list_custom_scripts()
            for script in kandji_scripts:
                download_script(script["id"], script_dir)

    if only_profiles:
        logger.info("Running Kandji profile portion only.")
        local_profiles = find_local_items(profile_dir, profile_ext, item_type="profile")
        kandji_profiles = list_custom_profiles()
        sync_kandji_profiles(local_profiles, kandji_profiles, dryrun)

        if delete:
            logger.info("Delete flag enabled. Comparing Kandji profiles with the local repo for potential deletions.")
            delete_items(kandji_profiles, local_profiles, delete_custom_profile, dryrun)

        if download:
            logger.info("Download flag enabled. Downloading all profiles from Kandji.")

            # Download profiles
            kandji_profiles = list_custom_profiles()
            for profile in kandji_profiles:
                download_profile(profile["id"], profile_dir)

    # Run both if neither flag is specified
    if not only_scripts and not only_profiles:
        logger.info("Running both Kandji script and profile portions.")
        # Find and sync scripts
        local_scripts = find_local_items(script_dir, script_ext, item_type="script")
        kandji_scripts = list_custom_scripts()
        sync_kandji_scripts(local_scripts, kandji_scripts, dryrun)

        # Find and sync profiles
        local_profiles = find_local_items(profile_dir, profile_ext, item_type="profile")
        kandji_profiles = list_custom_profiles()
        sync_kandji_profiles(local_profiles, kandji_profiles, dryrun)

        if delete:
            logger.info("Delete flag enabled. Comparing Kandji scripts and profiles with the local repo for potential deletions.")
            delete_items(kandji_scripts, local_scripts, delete_custom_script, dryrun)
            delete_items(kandji_profiles, local_profiles, delete_custom_profile, dryrun)

        if download:
            logger.info("Download flag enabled. Downloading all scripts and profiles from Kandji.")

            # Download scripts
            kandji_scripts = list_custom_scripts()
            for script in kandji_scripts:
                download_script(script["id"], script_dir)

            # Download profiles
            kandji_profiles = list_custom_profiles()
            for profile in kandji_profiles:
                download_profile(profile["id"], profile_dir)

if __name__ == "__main__":
    main()
