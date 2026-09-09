import hashlib # file intergrity monitor (FIM) monitors if your file has been edited,deleted,or moved
import json
import os


folder_path = input("Enter folder name or path: ").strip().strip("'\"")

if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
    print("Error: Invalid directory path.")
    raise SystemExit

baseline_file = "baseline.json"



def get_file_hash(filepath):
    
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536): 
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None



current_hashes = {}
for root, _, files in os.walk(folder_path):
    for filename in files:
        full_path = os.path.join(root, filename)
         
        rel_path = os.path.relpath(full_path, folder_path)

        file_hash = get_file_hash(full_path)
        if file_hash:
            current_hashes[rel_path] = file_hash


if not os.path.exists(baseline_file):
    with open(baseline_file, "w") as f:
        json.dump(current_hashes, f, indent=4)
    print("Baseline created successfully in 'baseline.json'. Run script again to check for changes.")


else:
    with open(baseline_file, "r") as f:
        baseline_hashes = json.load(f)

    print("\n--- Integrity Report ---")
    changes_detected = False


    for filepath, file_hash in current_hashes.items():
        if filepath not in baseline_hashes:
            print(f"[NEW FILE] {filepath}")
            changes_detected = True
        elif baseline_hashes[filepath] != file_hash:
            print(f"[MODIFIED] {filepath}")
            changes_detected = True

    
    for filepath in baseline_hashes:
        if filepath not in current_hashes:
            print(f"[DELETED]  {filepath}")
            changes_detected = True

    if not changes_detected:
        print("✓ All files are intact. No changes detected.")

    
    update = input("\nUpdate baseline with current state? (y/n): ").lower()
    if update == "y":
        with open(baseline_file, "w") as f:
            json.dump(current_hashes, f, indent=4)
        print("✓ Baseline updated.")
