import os
import requests
import traceback
import json
from datetime import datetime, timedelta
from dotenv import dotenv_values

def opener(path, flags):
    return os.open(path, flags, 0o600)

def main():
    print('Getting token')
    config = dotenv_values(dotenv_path='credentials')
    # check keys
    if not 'CLIENT_ID' in config:
        raise Exception('CLIENT_ID not found in credentials')
    
    if not 'CLIENT_SECRET' in config:
        raise Exception('CLIENT_SECRET not found in credentials')
    
    # make the call
    data = {
        'client_id': config['CLIENT_ID'],
        'client_secret': config['CLIENT_SECRET'],
        'audience': 'service',
        'grant_type': 'client_credentials'
    }
    url = 'https://grepr-prod.us.auth0.com/oauth/token'
    r = requests.post(url, json=data)
    print('Token Status {}'.format(r.status_code))
    r.raise_for_status()
    print('Saving token')
    authToken = r.json()
    fmt = '%Y-%m-%d %H:%M:%S'
    now = datetime.now()
    tz = now.astimezone().tzname()
    authToken['created'] = '{} {}'.format(now.strftime(fmt), tz)
    expires = now + timedelta(seconds=authToken['expires_in'])
    authToken['expiry'] = '{} {}'.format(expires.strftime(fmt), tz)
    with open('token.json', 'w', opener=opener) as f:
        f.write(json.dumps(authToken, indent=4))
    print('Token saved as token.json')

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        traceback.print_tb(e.__traceback__)
