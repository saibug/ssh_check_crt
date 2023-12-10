#!/usr/bin/env python

import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import requests
from datetime import datetime, timedelta


def check_ssl_certificate(crt_url, within_days):
    try:
        # Download the certificate from the URL
        response = requests.get(crt_url)
        certificate = response.text

        # Load and parse the certificate
        cert_data = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

        # Get the common name (CN) from the certificate
        common_name = cert_data.subject.rfc4514_string()

        # Check the validity dates of the certificate
        not_after = cert_data.not_valid_after

        # Calculate the number of days remaining until the expiration date
        days_left = (not_after - datetime.now()).days

        # Print the certificate details
        print(f"Common Name (CN): {common_name}")
        print(f"Days Remaining until Expiration: {days_left}")

        # Check if expiration is within n days
        if days_left <= int(within_days):
            print(f"Certificate expiration within {within_days} days!")

    except requests.exceptions.RequestException as e:
        print("Error downloading the certificate:", e)
    except Exception as e:
        print("Error loading or parsing the certificate:", e)


if __name__ == '__main__':
    if len(sys.argv) <= 2:
        print("Usage: python script.py <crt_url> <within_days>")
    else:
        crt_url = sys.argv[1]
        within_days = sys.argv[2]
        check_ssl_certificate(crt_url, within_days)
