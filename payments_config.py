# Fixed: CWE-798 Use of Hard-coded Credentials.
# Credentials and API keys are now read from the environment instead of
# being committed to source control.
import os
import psycopg2
import requests

DB_HOST = os.environ["DB_HOST"]
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]

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
