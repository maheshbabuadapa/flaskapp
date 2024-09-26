from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import os
import pandas as pd
import requests

# Environment variables for login credentials
aqua_id = os.getenv('AQUA_ID')
aqua_password = os.getenv('AQUA_PASSWORD')

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Required for flash messages

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
        return response.json()
    except requests.exceptions.HTTPError as err:
        print(f"HTTP Error occurred: {err}")
    except Exception as err:
        print(f"An error occurred: {err}")
    return None


# Function to compare and update vulnerabilities
def update_vulnerabilities(doc_application_data, base_image_data):
    # Extract list of CVE names from base_image.json
    base_image_cve_names = {cve['name'] for cve in base_image_data['cves']}

    # Update python.json CVEs with the base_image_vulnerability field
    for cve in doc_application_data['cves']:
        if cve['name'] in base_image_cve_names:
            cve['base_image_vulnerability'] = "yes"
        else:
            cve['base_image_vulnerability'] = "no"
    
    # Convert updated data to a DataFrame and save to an Excel file
    df = pd.DataFrame(doc_application_data['cves'])
    updated_filename = 'doc_application.xlsx'
    df.to_excel(updated_filename, index=False)
    return updated_filename


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get form data
        doc_application = request.form.get('doc_application')
        application_registry = request.form.get('application_registry')
        base_image = request.form.get('base_image')
        baseimage_registry = request.form.get('baseimage_registry')

        # Perform login
        token = perform_login()
        if not token:
            flash("Login failed. Please check your credentials.")
            return redirect(url_for('index'))

        # Construct URLs and fetch data
        scan_url_template = 'https://gis-container-scan.gob.com/api/v1/scanner/registry/{}/image/{}/scan-results'
        doc_application_url = scan_url_template.format(application_registry, doc_application)
        base_image_url = scan_url_template.format(baseimage_registry, base_image)

        doc_application_data = fetch_json_data(doc_application_url, token)
        base_image_data = fetch_json_data(base_image_url, token)

        if not doc_application_data or not base_image_data:
            flash("Failed to retrieve data for one or both images.")
            return redirect(url_for('index'))

        # Update vulnerabilities and save to Excel
        updated_filename = update_vulnerabilities(doc_application_data, base_image_data)
        return send_file(updated_filename, as_attachment=True)

    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=8000)


