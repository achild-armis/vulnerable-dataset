# CWE-798: Use of Hard-coded Credentials
# Vulnerable: database and API credentials hardcoded directly in source.
import os

import psycopg2
import requests

# FIXED: credentials are now loaded from the environment instead of being
# hardcoded in source.
DB_HOST = "prod-db.internal.company.com"
DB_USER = "admin"
DB_PASSWORD = os.environ["DB_PASSWORD"]

# FIXED: third-party API key and signing secret loaded from the environment.
STRIPE_API_KEY = os.environ["STRIPE_API_KEY"]
SECRET_SIGNING_KEY = os.environ["SECRET_SIGNING_KEY"]


def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname="production",
    )


def charge_customer(amount, token):
    response = requests.post(
        "https://api.stripe.com/v1/charges",
        headers={"Authorization": f"Bearer {STRIPE_API_KEY}"},
        data={"amount": amount, "source": token, "currency": "usd"},
    )
    return response.json()
