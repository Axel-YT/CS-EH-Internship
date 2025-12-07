"""
File Integrity Checker
----------------------

What this script does:
1. Creates a *baseline* of files and their hash values (first run).
2. Later, checks the same folder again and compares:
   - Shows files that are NEW
   - Shows files that are DELETED
   - Shows files that are MODIFIED

Hash Algorithm used: SHA-256 (from hashlib)
Baseline is stored in: file_hashes.json (same folder as this script)
"""

import os          # For working with files and directories
import hashlib     # For calculating hash values
import json        # For saving and loading baseline data in JSON format

# Name of the file where we will store all file hashes (baseline)
BASELINE_FILE = "file_hashes.json"


def get_file_hash(file_path):
    """
    Calculate and return the SHA-256 hash of the given file.

    file_path: full path of the file on disk
    returns: hex string of hash (or None if file cannot be read)
    """
    hasher = hashlib.sha256()  # Create a SHA-256 hash object

    try:
        # Open file in binary mode (rb = read binary)
        with open(file_path, "rb") as f:
            while True:
                # Read file in chunks (4096 bytes at a time)
                chunk = f.read(4096)
                if not chunk:
                    break  # End of file
                hasher.update(chunk)  # Add this chunk to the hash
    except (PermissionError, FileNotFoundError):
        # If we cannot read the file (no permission or missing), return None
        return None

    # Return the final hash as a hexadecimal string
    return hasher.hexdigest()


def scan_directory(directory):
    """
    Walk through all files inside 'directory' and compute their hashes.

    directory: folder path to scan
    returns: dictionary like {relative_file_path: hash_value}
             example: {"subfolder/test.txt": "abc123..."}
    """
    file_hashes = {}

    # Convert directory path to absolute path (for safety)
    directory = os.path.abspath(directory)

    # os.walk goes through all subfolders and files
    for root, dirs, files in os.walk(directory):
        for name in files:
            # Full path of file
            file_path = os.path.join(root, name)

            # Relative path (relative to the main directory)
            # This helps to make paths shorter and more portable
            rel_path = os.path.relpath(file_path, directory)

            # Get hash of this file
            file_hash = get_file_hash(file_path)

            # If hash is not None, save it in dictionary
            if file_hash is not None:
                file_hashes[rel_path] = file_hash

    return file_hashes


def create_baseline(directory):
    """
    Create a baseline of hash values for all files in the given directory.

    It will:
    1. Scan the directory and get hashes.
    2. Save them into BASELINE_FILE as JSON.
    """
    print(f"Scanning directory: {directory}")
    hashes = scan_directory(directory)

    # Prepare data to save
    data_to_save = {
        "directory": os.path.abspath(directory),  # which folder we scanned
        "hashes": hashes                          # all file hashes
    }

    # Save dictionary as JSON into BASELINE_FILE
    with open(BASELINE_FILE, "w") as f:
        json.dump(data_to_save, f, indent=4)

    print(f"\nBaseline created and saved to '{BASELINE_FILE}'.")
    print(f"Total files scanned: {len(hashes)}")


def check_integrity(directory):
    """
    Compare current file hashes with the baseline.

    It will:
    1. Load baseline from BASELINE_FILE.
    2. Scan current directory again.
    3. Find:
       - Deleted files (were in baseline, not now)
       - New files (are now, not in baseline)
       - Modified files (same path, different hash)
    4. Print a simple report.
    """
    # First check if baseline file exists
    if not os.path.exists(BASELINE_FILE):
        print(f"Baseline file '{BASELINE_FILE}' not found.")
        print("Please run 'Create baseline' option first.")
        return

    # Load baseline data from JSON
    with open(BASELINE_FILE, "r") as f:
        baseline_data = json.load(f)

    baseline_dir = baseline_data["directory"]   # folder used when baseline was created
    baseline_hashes = baseline_data["hashes"]   # old hashes

    # Check if user is scanning the same directory as before
    if os.path.abspath(directory) != baseline_dir:
        print("WARNING: You are checking a different directory than in baseline.")
        print(f"Baseline directory : {baseline_dir}")
        print(f"Current directory  : {os.path.abspath(directory)}\n")

    print(f"Scanning current directory: {directory}")
    current_hashes = scan_directory(directory)

    # Convert keys (file paths) to sets for easy comparison
    baseline_files = set(baseline_hashes.keys())
    current_files = set(current_hashes.keys())

    # Files that were in baseline but are missing now
    deleted_files = baseline_files - current_files

    # Files that are new (not in baseline)
    new_files = current_files - baseline_files

    # Files present in both baseline and current
    common_files = baseline_files & current_files

    # List to store files whose content has changed
    modified_files = []

    for file in common_files:
        # Compare old hash and new hash
        if baseline_hashes[file] != current_hashes[file]:
            modified_files.append(file)

    # ----- Print the final report -----
    print("\n========== FILE INTEGRITY REPORT ==========")

    # If no changes found
    if not deleted_files and not new_files and not modified_files:
        print("No changes detected. All files are intact.")
    else:
        # Show deleted files
        if deleted_files:
            print("\nDeleted files:")
            for fpath in sorted(deleted_files):
                print("  -", fpath)

        # Show new files
        if new_files:
            print("\nNew files:")
            for fpath in sorted(new_files):
                print("  +", fpath)

        # Show modified files
        if modified_files:
            print("\nModified files:")
            for fpath in sorted(modified_files):
                print("  *", fpath)

    print("\nTotal files in baseline:", len(baseline_files))
    print("Total files now        :", len(current_files))
    print("===========================================\n")


def main():
    """
    Main function that shows a small menu to the user.

    Steps:
    1. Ask user to choose:
       - 1: Create baseline
       - 2: Check integrity
    2. Ask for directory path.
    3. Call respective function.
    """
    print("=== FILE INTEGRITY CHECKER ===")
    print("1. Create baseline (first time)")
    print("2. Check integrity (compare with baseline)")
    choice = input("Enter your choice (1 or 2): ").strip()

    directory = input("Enter the directory path to monitor: ").strip()

    if choice == "1":
        create_baseline(directory)
    elif choice == "2":
        check_integrity(directory)
    else:
        print("Invalid choice. Please run the program again.")


# This ensures main() runs only when this file is executed directly
if __name__ == "__main__":
    main()
