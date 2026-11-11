
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict, deque

LOG_FILE = "final_5more_failed.evtx"
THRESHOLD = 5
WINDOW_MINUTES = 5

events = []

# Step 1: Read failed logon events from the EVTX file
with Evtx(LOG_FILE) as log:
    for record in log.records():
        try:
            root = ET.fromstring(record.xml())

            event_id = root.findtext(".//{*}EventID")

            if event_id != "4625":
                continue

            # Extract event timestamp
            time_element = root.find(".//{*}TimeCreated")
            if time_element is None:
                continue

            timestamp = time_element.attrib.get("SystemTime")
            if not timestamp:
                continue

            event_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            # Extract useful Windows event data
            details = {}
            for item in root.findall(".//{*}EventData/{*}Data"):
                details[item.attrib.get("Name", "")] = item.text or ""

            username = details.get("TargetUserName", "Unknown")
            source_ip = details.get("IpAddress", "Unknown")

            events.append({
                "time": event_time,
                "username": username,
                "ip": source_ip
            })

        except (ET.ParseError, ValueError, TypeError) as error:
            print(f"Skipping unreadable event: {error}")

# Step 2: Process events in chronological order
events.sort(key=lambda event: event["time"])

# Keep a separate rolling window for each username and source IP
attempts = defaultdict(deque)
alerts = 0

print(f"Failed logon events found: {len(events)}")
print(f"Detection threshold: {THRESHOLD} failures "
      f"within {WINDOW_MINUTES} minutes\n")

# Step 3: Detect repeated failed logons
for event in events:
    key = (event["username"], event["ip"])
    recent = attempts[key]
    current_time = event["time"]

    cutoff = current_time - timedelta(minutes=WINDOW_MINUTES)

    # Remove attempts outside the five-minute window
    while recent and recent[0] < cutoff:
        recent.popleft()

    recent.append(current_time)

    # Alert when the fifth qualifying attempt is reached
    if len(recent) == THRESHOLD:
        alerts += 1
        print("!!! BRUTE-FORCE DETECTION ALERT !!!")
        print(f"Username: {event['username']}")
        print(f"Source IP: {event['ip']}")
        print(f"Failed attempts: {len(recent)}")
        print(f"Window: {WINDOW_MINUTES} minutes")
        print(f"Latest event: {current_time.isoformat()}")
        print("-" * 40)

# Step 4: Report the result
if alerts == 0:
    print("No threshold-triggering activity detected.")
else:
    print(f"\nTotal detection alerts: {alerts}")

