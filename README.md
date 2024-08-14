# git2kandji

## About
This `python3` script leverages the [Kandji API](https://api-docs.kandji.io) to accomplish a couple of things:
* Sync custom scripts from a repository (local or git) to Kandji
* Sync custom profiles from a repository (local or git) to Kandji

## Overview
**Git2Kandji** is a powerful tool designed to synchronize custom scripts and custom profiles between your Git repository and Kandji. By ensuring that the latest configurations from your Git repository are always up-to-date in Kandji, it helps minimize manual errors and maintain consistency across your managed devices.

## Key Features
- Automated CI/CD Integration: Ideal for setting up a CI/CD pipeline, allowing seamless updates to Kandji each time changes are pushed to your repository.

- Script and Profile Synchronization:
  - Creation: If a script or profile exists in the repository but not in Kandji, the tool will automatically create it in Kandji.
  - Updating: The tool compares the hash of each script and profile in Kandji against the repository version. If differences are found, it updates Kandji to match the repository, which is treated as the source of truth.
- Profile Specific Handling: For profiles, the tool ignores changes to PayloadDisplayName, PayloadIdentifier, PayloadUUID, and PayloadScope at the root level when comparing, as these are modified by Kandji after upload.
- Cleanup: When enabled, the tool can delete any scripts or profiles in Kandji that are not present in the repository, keeping your Kandji environment in sync with your source of truth.

## How It Works
1. Repository Scanning: The tool scans your specified repository (or any subfolder of your choice) for scripts and profiles.
2. Comparison & Synchronization:
  - Scripts: Names and hashes are compared between Kandji and the repository. Differences trigger updates, ensuring Kandji always reflects the latest state in your Git repository.
  - Profiles: The same process is followed for profiles, with special handling to account for fields that Kandji modifies after profile upload.
3. Optional Deletion: If enabled, the tool will remove any scripts or profiles in Kandji that are not found in the repository, ensuring that your Kandji environment matches your repository exactly.

## Future State
- Slack Notifications
- Sync audit, preinstall, and postinstall scripts for Custom Apps
- Sync preinstall and postinstall scripts for Custom Printers (still need an API endpoint for this)
- Sync Bookmarks (still need an API endpoint for this)

## Requirements
- `python3`
- Python dependencies - Can be installed using the included `requirements.txt` using the command `python3 -m pip install -r requirements.txt` or individually using the command `python3 -m pip install requests`.
- A [Kandji API Token](https://support.kandji.io/support/solutions/articles/72000560412-kandji-api) with the following permissions:
    - Custom Scripts
        - Create Custom Script
        - Update Custom Script
        - List Custom Scripts
        - Delete Custom Script (this is not needed if you won't be using the --delete argument)
    - Custom Profiles
        - Create Custom Profile
        - Update Custom Profile
        - List Custom Profile
        - Delete Custom Profile (this is not needed if you won't be using the --delete argument)
    <img alt="API Permissions" src="https://github.com/moojomoore/git2kandji/blob/main/images/kandji-api-requirements.png">
- Custom Scripts and/or Custom Profiles

## Configuration
Kandji Subdomain, Region, and API Token can be passed either as an environment variable or as an argument to the script.
To set environment variables:
```bash
export INPUT_KANDJI_SUBDOMAIN=kandji-subdomain-here
export INPUT_KANDJI_REGION=kandji-region-here
export INPUT_KANDJI_TOKEN=kandji-api-token-here
```

## Deployment
Pass API Information as an argument:
```bash
python3 git2kandji.py --subdomain accuhive --region us --token abcd1234
```

Run Full Synchronization:
```bash
python3 git2kandji.py
```

Run Only Script Synchronization:
```bash
python3 git2kandji.py --only-scripts
```

Run Only Profile Synchronization:
```bash
python3 git2kandji.py --only-profiles
```

Dry Run:
```bash
python3 git2kandji.py --dryrun
```

Delete Untracked Items in Kandji:
```bash
python3 git2kandji.py --delete
```

Custom Logging Level:
```bash
python3 git2kandji.py --log-level DEBUG
```

## Usage
```
usage: git2kandji [-h] [--script-dir SCRIPT_DIR] [--script-ext SCRIPT_EXT]
                  [--profile-dir PROFILE_DIR] [--subdomain SUBDOMAIN]
                  [--region {us,eu}] [--token TOKEN] [--delete]
                  [--only-scripts] [--only-profiles] [--dryrun]
                  [--log-level {DEBUG,INFO,WARNING,ERROR}] [--version]

Git2Kandji - Sync Git Repo with Kandji.

options:
  -h, --help            show this help message and exit
  --script-dir SCRIPT_DIR
                        directory containing script files (e.g. custom-
                        scripts)
  --script-ext SCRIPT_EXT
                        space-separated list of file extensions to process
                        (e.g., .sh .py .zsh)
  --profile-dir PROFILE_DIR
                        directory containing profile files (e.g. custom-
                        profiles)
  --subdomain SUBDOMAIN
                        Kandji subdomain (overrides global environment
                        variable)
  --region {us,eu}      Kandji region (overrides global environment variable)
  --token TOKEN         Kandji API token (overrides global environment
                        variable)
  --delete              Delete Kandji library items not present in local
                        repository
  --only-scripts        Only run the Kandji script portion
  --only-profiles       Only run the Kandji profile portion
  --dryrun              Compares Kandji to local repository and outputs any
                        changes to be made
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Set the logging level
  --version             show this script's version
```

## Testing
It is recommended that you use a test/dev Kandji instance for testing.
If you do not have a test/dev Kandji instance, you can use the `--dryrun` argument to prevent any changes from happening in Kandji.

## Acknowledgements
**git2kandji** is inspired by [git2jss](https://github.com/badstreff/git2jss) and [git2jamf](https://github.com/jgarcesres/git2jamf). Shout out to the [Kandji Github](https://github.com/kandji-inc) for having great API examples.

## Contributions
Contributions are welcome and greatly appreciated! If you have ideas for improvements or have found a bug, please feel free to contribute