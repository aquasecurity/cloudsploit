import json
import requests
import google.auth
from google.oauth2 import service_account
from google.auth.transport import requests as auth_requests

def invoke_cloudsploit_scanner(function_url, key_path, settings):
    """
    Makes an authenticated POST request to the deployed CloudSploit scanner function.
    This function generates an OIDC token directly from the service account key.

    Args:
        function_url (str): The trigger URL of the deployed Cloud Function.
        key_path (str): The file path to the GCP service account key JSON file.
        settings (dict): A dictionary of settings for the scan.
    """
    try:
        # --- Programmatic Authentication ---
        # Instead of calling the gcloud CLI, we use the google-auth library
        # to generate an identity token for the function's URL (the audience).
        print(f"Generating auth token for audience: {function_url}")
        auth_req = auth_requests.Request()
        creds = service_account.IDTokenCredentials.from_service_account_file(
            key_path,
            target_audience=function_url
        )
        creds.refresh(auth_req)
        auth_token = creds.token
        print("Successfully generated auth token from service account key.")
        
        headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        }

        # Load the service account key to be sent in the request body
        with open(key_path, 'r') as f:
            service_account_key = json.load(f)

        payload = {
            "serviceAccount": service_account_key,
            "settings": settings
        }
        
        print(f"\nSending POST request to: {function_url}")
        print(f"Requesting scan for plugin: {settings.get('plugin', 'all')}")
        
        response = requests.post(function_url, headers=headers, json=payload, timeout=600) # 10 minute timeout

        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status()

        print("\n--- SCAN RESULTS (JSON) ---")
        # Pretty-print the JSON response
        print(json.dumps(response.json(), indent=2))

    except requests.exceptions.RequestException as e:
        print("\n--- REQUEST FAILED ---")
        print(f"An error occurred while making the request: {e}")
        if e.response is not None:
            print(f"Status Code: {e.response.status_code}")
            print(f"Response Body: {e.response.text}")
    except Exception as e:
        print("\n--- SCRIPT ERROR ---")
        print(f"An unexpected error occurred: {e}")
        print("Please ensure the service account has the 'Cloud Functions Invoker' and 'Service Account Token Creator' roles.")


if __name__ == '__main__':
    # --- CONFIGURATION ---
    # IMPORTANT: Replace this with the actual URL of your deployed function.
    FUNCTION_URL = "https://cloudsploit-scanner-254116077699.europe-west1.run.app"
    KEY_FILE_PATH = 'key.json'

    # --- EXECUTION ---
    try:
        # Define the settings for this specific scan
        scan_settings = {
            "plugin": "automaticRestartEnabled"
        }
        
        # Call the function which now handles all logic
        invoke_cloudsploit_scanner(FUNCTION_URL, KEY_FILE_PATH, scan_settings)
        
    except Exception as e:
        # The function now has its own error handling, but we catch any final issues.
        print(f"\nScript failed to complete.")

