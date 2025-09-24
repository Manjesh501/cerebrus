#!/usr/bin/env python3
import requests

# Test file upload to the analyze endpoint
url = "http://localhost:5000/api/analyze"

# Create a test file
with open("test_upload_file.txt", "w") as f:
    f.write("This is a test file for malware analysis.")

# Upload the file
try:
    with open("test_upload_file.txt", "rb") as f:
        files = {"file": ("test_upload_file.txt", f, "text/plain")}
        response = requests.post(url, files=files)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
except Exception as e:
    print(f"Error: {e}")