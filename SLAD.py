import os # Suspicious Login Activity Detector(SLAD), A Python program use to analyze logins to identify potential dangerous patterns like brute force attacks and more  
from datetime import datetime, timedelta

filename = input("Enter log file name: ")

script_dir = os.path.dirname(os.path.abspath(__file__))
working_dir = os.getcwd()

candidates = []
if os.path.isabs(filename):
    candidates.append(filename)
else:
    candidates.append(filename)
    candidates.append(os.path.join(working_dir, filename))
    candidates.append(os.path.join(script_dir, filename))

resolved_path = None
for candidate in candidates:
    if os.path.isfile(candidate):
        resolved_path = candidate
        break

if resolved_path is None:
    print(f"Error: File '{filename}' was not found.")
    print(f"Python is currently looking in: {working_dir}")
    print(f"The script folder is: {script_dir}")
    print("Reason: Python searches the current working directory unless you give a full path or a path relative to the script folder.")
    raise SystemExit

try:
    file = open(resolved_path, "r", encoding="utf-8")
except FileNotFoundError:
    print(f"Error: File '{filename}' was not found.")
    raise SystemExit


events = []

success = 0
failed = 0

failed_ip = {}
failed_user = {}

brute_force = []
compromise = []

FAIL_LIMIT = 5
TIME_LIMIT = timedelta(minutes=2)

for line in file:

    line = line.strip()

    if line == "":
        continue

    parts = line.split()

    if len(parts) < 5:
        continue

    try:
        timestamp = datetime.strptime(parts[0] + " " + parts[1],
                                     "%Y-%m-%d %H:%M:%S")
        event = parts[2]
        user = parts[3].split("=")[1]
        ip = parts[4].split("=")[1]
    except (ValueError, IndexError):
        continue

    if event not in ("LOGIN_SUCCESS", "LOGIN_FAILED"):
        continue

    events.append([timestamp, event, user, ip])

file.close()

for event in events:

    if event[1] == "LOGIN_SUCCESS":
        success += 1

    else:
        failed += 1

        ip = event[3]
        user = event[2]

        failed_ip[ip] = failed_ip.get(ip, 0) + 1
        failed_user[user] = failed_user.get(user, 0) + 1

for ip in failed_ip:

    if failed_ip[ip] >= FAIL_LIMIT:
        brute_force.append(ip)

for i in range(len(events)):

    if events[i][1] == "LOGIN_SUCCESS":

        user = events[i][2]
        ip = events[i][3]
        success_time = events[i][0]

        count = 0

        for j in range(i):

            if events[j][1] == "LOGIN_FAILED":

                if events[j][2] == user and events[j][3] == ip:

                    difference = success_time - events[j][0]

                    if difference <= TIME_LIMIT:
                        count += 1 

        if count >= 3:
            compromise.append([user, ip, count])

print("\n========== SECURITY REPORT ==========")

print("Total Events:", len(events))
print("Successful Logins:", success)
print("Failed Logins:", failed)

print("\nFailed Attempts By IP")

for ip in failed_ip:
    print(ip, ":", failed_ip[ip])

print("\nPotential Brute Force")

if len(brute_force) == 0:
    print("None")

else:
    for ip in brute_force:
        print("[HIGH]", ip, "generated", failed_ip[ip], "failed logins")

print("\nSuccessful Login After Failures")

if len(compromise) == 0:
    print("None")

else:
    for alert in compromise:

        print("[MEDIUM]")
        print("User:", alert[0])
        print("IP:", alert[1])
        print("Failed Attempts:", alert[2])

print("\nAnalysis Complete")
