# CWE-798: Use of Hard-coded Credentials
# Vulnerable: database and API credentials hardcoded directly in source.
import psycopg2
import requests

# VULNERABLE: hardcoded database password
DB_HOST = "prod-db.internal.company.com"
DB_USER = "admin"
DB_PASSWORD = "Sup3rSecretPass2024!"

# VULNERABLE: hardcoded third-party API key
STRIPE_API_KEY = "sk_live_51HExampleKeyDoNotUseThisInRealCode"
SECRET_SIGNING_KEY = "my-app-jwt-secret-do-not-share"


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
