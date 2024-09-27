from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_wtf import CSRFProtect
import os
import pandas as pd
import requests

# Environment variables for login credentials
aqua_id = os.getenv('AQUA_ID')
aqua_password = os.getenv('AQUA_PASSWORD')

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Required for sessions and CSRF protection
csrf = CSRFProtect(app)  # Enable CSRF protection

# Function to perform login and retrieve the token
def perform_login():
    AQUA_LOGIN_URL = 'https://gis-container-scan.gob.com/api/v1/login'
    headers = {'Content-Type': 'application/json'}

    data = {
        'id': aqua_id,
        'password': aqua_password,
    }
    try:
        response = requests.post(AQUA_LOGIN_URL, json=data, headers=headers, verify=False)
        response.raise_for_status()
        token = response.json().get('token')
        print(f"Login successful. Token received: {token}")
        return token
    except requests.exceptions.HTTPError as err:
        print(f"HTTP Error occurred during login: {err}")
    except Exception as err:
        print(f"An error occurred during login: {err}")
    return None


# Function to fetch JSON data from the provided URL with the token
def fetch_json_data(url, token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Data fetched from {url}: {response.json()}")
        return response.json()
    except requests.exceptions.HTTPError as err:
        print(f"HTTP Error occurred while fetching data: {err}")
    except Exception as err:
        print(f"An error occurred while fetching data: {err}")
    return None


# Function to compare and update vulnerabilities
def update_vulnerabilities(doc_application_data, base_image_data):
    # Print data for debugging
    print(f"Doc Application Data: {doc_application_data}")
    print(f"Base Image Data: {base_image_data}")

    # Check if keys 'cves' are present in both data sets
    if 'cves' not in doc_application_data or 'cves' not in base_image_data:
        print("Error: 'cves' key missing in data.")
        return None

    # Extract list of CVE names from base_image.json
    base_image_cve_names = {cve['name'] for cve in base_image_data['cves']}
    print(f"Base Image CVE Names: {base_image_cve_names}")

    # Update python.json CVEs with the base_image_vulnerability field
    for cve in doc_application_data['cves']:
        if cve['name'] in base_image_cve_names:
            cve['base_image_vulnerability'] = "yes"
        else:
            cve['base_image_vulnerability'] = "no"
    
    # Convert updated data to a DataFrame and print for debugging
    df = pd.DataFrame(doc_application_data['cves'])
    print(f"Updated DataFrame: \n{df}")

    # Save to Excel file
    updated_filename = 'doc_application.xlsx'
    df.to_excel(updated_filename, index=False)
    print(f"Updated vulnerabilities saved to {updated_filename}")
    return updated_filename


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get form data (no longer fetching application_registry and baseimage_registry)
        doc_application = request.form.get('doc_application')
        base_image = request.form.get('base_image')

        # Hard-coded values for application_registry and baseimage_registry
        application_registry = 'application-registry'
        baseimage_registry = 'baseimage-registry'

        print(f"Form Data - Doc Application: {doc_application}, Base Image: {base_image}")
        print(f"Hard-coded Registries - Application Registry: {application_registry}, Base Image Registry: {baseimage_registry}")

        # Perform login
        token = perform_login()
        if not token:
            flash("Login failed. Please check your credentials.")
            return redirect(url_for('index'))

        # Construct URLs and fetch data
        scan_url_template = 'https://gis-container-scan.gob.com/api/v1/scanner/registry/{}/image/{}/scan-results'
        doc_application_url = scan_url_template.format(application_registry, doc_application)
        base_image_url = scan_url_template.format(baseimage_registry, base_image)

        print(f"Doc Application URL: {doc_application_url}")
        print(f"Base Image URL: {base_image_url}")

        doc_application_data = fetch_json_data(doc_application_url, token)
        base_image_data = fetch_json_data(base_image_url, token)

        if not doc_application_data or not base_image_data:
            flash("Failed to retrieve data for one or both images.")
            return redirect(url_for('index'))

        # Update vulnerabilities and save to Excel
        updated_filename = update_vulnerabilities(doc_application_data, base_image_data)
        if updated_filename:
            return send_file(updated_filename, as_attachment=True)
        else:
            flash("An error occurred while processing the data.")
            return redirect(url_for('index'))

    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=8000)
