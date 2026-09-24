# Sample Python file with hardcoded secrets
import requests

AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1'

SENDGRID_API_KEY = 'SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjK'

DATABASE_URL = 'mongodb://root:mongopassword456@mongo.example.com:27017/production'

def get_data():
    headers = {'Authorization': f'Bearer {SENDGRID_API_KEY}'}
    return requests.get('https://api.example.com', headers=headers)
