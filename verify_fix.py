
import requests
import time
import sys
import subprocess
import json

DETECTDOJO_URL = "http://localhost:8081"

def wait_for_service(url, timeout=60):
    print(f"Waiting for {url}...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{url}/health")
            if response.status_code == 200:
                print(f"{url} is ready!")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(2)
    print(f"Timeout waiting for {url}")
    return False

def add_finding():
    print("Adding a test finding...")
    payload = {
        "tool_name": "verification_script",
        "target_domain": "verification.local",
        "tool_output": "This is a test finding for verification."
    }
    try:
        response = requests.post(f"{DETECTDOJO_URL}/api/findings/add", json=payload)
        if response.status_code == 200:
            print("Finding added successfully.")
            return True
        else:
            print(f"Failed to add finding: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"Error adding finding: {e}")
        return False

def check_finding():
    print("Checking if finding exists...")
    # The assessment ID format is deterministic in our code: assessment_{target}_{date}
    # But let's list assessments first to get the ID
    try:
        response = requests.get(f"{DETECTDOJO_URL}/api/assessments")
        if response.status_code != 200:
            print(f"Failed to list assessments: {response.status_code}")
            return False
        
        assessments = response.json().get('assessments', [])
        found = False
        for assessment in assessments:
            if assessment['target'] == 'verification.local':
                assessment_id = assessment['assessment_id']
                print(f"Found assessment: {assessment_id}")
                
                # Check specifics
                resp = requests.get(f"{DETECTDOJO_URL}/api/findings/{assessment_id}")
                findings = resp.json().get('findings', [])
                if findings:
                    print(f"Found {len(findings)} findings.")
                    found = True
                break
        
        if found:
            print("Finding confirmed.")
            return True
        else:
            print("Finding NOT found.")
            return False
            
    except Exception as e:
        print(f"Error checking finding: {e}")
        return False

def restart_detectdojo():
    print("Restarting detectdojo container...")
    try:
        subprocess.run(["docker", "compose", "restart", "detectdojo"], check=True)
        print("Container restarted.")
    except subprocess.CalledProcessError as e:
        print(f"Error restarting container: {e}")
        return False
    return True

def main():
    if not wait_for_service(DETECTDOJO_URL):
        sys.exit(1)
        
    if not add_finding():
        sys.exit(1)
        
    if not check_finding():
        sys.exit(1)
        
    if not restart_detectdojo():
        sys.exit(1)
        
    # Wait for it to come back up
    if not wait_for_service(DETECTDOJO_URL):
        sys.exit(1)
        
    print("Verifying persistence after restart...")
    if check_finding():
        print("SUCCESS: Persistence verified!")
        sys.exit(0)
    else:
        print("FAILURE: Persistence failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
