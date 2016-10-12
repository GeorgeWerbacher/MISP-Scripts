import requests
import keys


def get_document(url):
    idef_url = url
    headers = {
        "Content-Type": "application/json",
        'auth-token': keys.idef_token
    }
    r = requests.get(idef_url, headers=headers)
    return r.json()

def get_vulnerability(url):
    data = get_document(url)
    vuln_key = data['key']
    vuln_key_type = data['keytype']
    uuid = data['uuid']


def get_file(url):
    file_url = url
    data = get_document(file_url)
    md5 = data['key']
    return md5


def get_threat_actor(url):
    actor_url = url
    data = get_document(actor_url)
    actor = data['key']
    return actor

