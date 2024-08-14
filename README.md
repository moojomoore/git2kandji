# git2kandji

## About
This `python3` script leverages the [Kandji API](https://api-docs.kandji.io) to accomplish a couple of things:
* Sync custom scripts from a repository (local or git) to Kandji
* Sync custom profiles from a repository (local or git) to Kandji

## Overview
**Git2Kandji** is designed to synchronize custom scripts and custom profiles between your Git repository and Kandji. By ensuring that the latest configurations from your Git repository are always up-to-date in Kandji, it helps minimize manual errors and maintain consistency across your managed devices.

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

## Testing
It is recommended that you use a test/dev Kandji instance for testing.
If you do not have a test/dev Kandji instance, you can use the `--dryrun` argument to prevent any changes from happening in Kandji.

## Acknowledgements
**git2kandji** is inspired by [git2jss](https://github.com/badstreff/git2jss) and [git2jamf](https://github.com/jgarcesres/git2jamf). Shout out to the [Kandji Github](https://github.com/kandji-inc) for having great API examples.

## Contributions
Contributions are welcome and greatly appreciated! If you have ideas for improvements or have found a bug, please feel free to contribute