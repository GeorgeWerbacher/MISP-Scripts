import requests
import keys
from pymisp import PyMISP
misp = PyMISP(keys.misp_url, keys.misp_key, False, 'json')

def get_document(url):
    idef_url = url
    headers = {
        "Content-Type": "application/json",
        'auth-token': keys.idef_token
    }
    r = requests.get(idef_url, headers=headers)
    return r.json()

def get_region(url):
    data = get_document(url)

    for i in data['links']:
        if i['type'] == 'region':
            return i['key']

def get_detection_signature(event, url):
    data = get_document(url)

    # Add Kill Chain Tags
    if data['kill_chain'] == 'Reconnaissance':
        misp.add_tag(event, 'kill-chain:Reconnaissance')
    if data['kill_chain'] == 'Weaponization':
        misp.add_tag(event, 'kill-chain:Weaponization')
    if data['kill_chain'] == 'Actions on Objectives':
        misp.add_tag(event, 'kill-chain:Actions on Objectives')
    if data['kill_chain'] == 'Command and Control':
        misp.add_tag(event, 'kill-chain:Command and Control')
    if data['kill_chain'] == 'Delivery':
        misp.add_tag(event, 'kill-chain:Delivery')
    if data['kill_chain'] == 'Exploitation':
        misp.add_tag(event, 'kill-chain:Exploitation')
    if data['kill_chain'] == 'Installation':
        misp.add_tag(event, 'kill-chain:Installation')


def import_intelligence_alert(url, case_name, case_date):
    event = misp.new_event(1, 4, 0, info='Intelligence Alert: %s' % case_name, date=case_date)
    print 'Successfully created Event....'

    data = get_document(url)
    created_on = data['results'][0]['created_on']

    for indicators in data['results'][0]['links']:

        # COUNTRY
        if indicators['type'] == 'country':
            country = indicators['key']
            misp.add_named_attribute(event, 'Attribution', 'comment', country, comment='Country')   # Created Attribution
            country_url = keys.idef_base_url + indicators['href']
            #region = get_region(country_url)
            #tag = region + ':' + country        # Adds Tag
            #misp.new_tag(tag,exportable=True)
            #misp.add_tag(event, tag)

        if indicators['type'] == 'region':
            region = indicators['key']
            misp.add_named_attribute(event, 'Attribution', 'comment', region, comment='Region')

        if indicators['type'] == 'detection_signature':
            detection_signature = indicators['key']
            misp.add_detection_name(event, detection_signature)
            dectection_url = keys.idef_base_url + indicators['href']
            get_detection_signature(event, url=dectection_url)





