
import requests

def submit_job():
    url = 'http://localhost:5001/submit'
    try:
        with open('sample.bin', 'rb') as f:
            files = {'file': ('sample.bin', f, 'application/octet-stream')}
            print(f"Submitting job to {url}...")
            r = requests.post(url, files=files)
            print(f"Status: {r.status_code}")
            print(f"Response: {r.text}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == '__main__':
    submit_job()
