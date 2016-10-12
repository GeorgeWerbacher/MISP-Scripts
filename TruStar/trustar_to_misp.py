from pymisp import PyMISP
import requests
import keys
from misp_import import search_events, create_event
misp = PyMISP(keys.misp_url, keys.misp_key, False, 'json')


def get_token():
    client_auth = requests.auth.HTTPBasicAuth(keys.tru_key, keys.tru_secret)
    post_data = {"grant_type": "client_credentials"}
    resp = requests.post(keys.tru_token_url, auth=client_auth, data=post_data)
    token_json = resp.json()
    return token_json["access_token"]


def get_reports(access_token):
    headers = {"Authorization": "Bearer " + access_token}
    resp = requests.get(keys.tru_api_url, headers=headers)
    return resp.json()


if __name__ == "__main__":
    data = get_reports(get_token())
    for case in data:
        case_name = case['title']
        if search_events(case_name=case_name) is not None:
            print 'Case Already Exists'
        else:
            create_event(data=case)
