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

    try:
        for source in data['sources_external']:
            try:
                description = source['description']
                misp.add_named_attribute(event, 'External analysis', 'link', value=source['url'], comment=description)
            except KeyError:
                misp.add_named_attribute(event, 'External analysis', 'link', value=source['url'])
    except KeyError:
        pass

    try:
        if data['signature_type'] == 'snort':
            misp.add_snort(event, data['key'])
        if data['signature_type'] == 'yara':
            misp.add_yara(event, data['key'])
    except KeyError:
        misp.add_snort(event, data['key'])


def get_domain(event,url):
    data = get_document(url)

    try:
        for source in data['sources_external']:
            misp.add_named_attribute(event, 'External analysis', 'link', value=source['url'], comment=source['description'])
    except KeyError:
        pass

    try:
        misp.add_domain(event, domain=data['key'], comment=data['meta_data'])
    except KeyError:
        misp.add_domain(event, domain=data['key'])


def get_file(event, url):
    data = get_document(url)

    if data['sha1'] is not None:
        misp.add_hashes(event, sha1=data['sha1'], comment=data['file_class'])
    if data['sha256'] is not None:
        misp.add_hashes(event, sha256=data['sha256'], comment=data['file_class'])

    return data['file_class']


def get_global_event(event, url):
    data = get_document(url)
    key = data['key']
    try:
        description = data['description']
    except KeyError:
        description = None
        pass
    misp.add_named_attribute(event, 'External analysis', 'other', value='Global Event: %s' % key, comment=description)

    for source in data['sources_external']:
        misp.add_named_attribute(event, 'External analysis', 'link', value=source['url'], comment=source['description'])


def get_ip(event, url):
    data = get_document(url)

    try:
        misp.add_ipdst(event, ipdst=data['key'], comment=data['meta_data'])
    except KeyError:
        misp.add_ipdst(event, ipdst=data['key'])


def import_intelligence_alert(url, case_name, case_date):
    event = misp.new_event(1, 4, 0, info='Intelligence Alert: %s' % case_name, date=case_date)
    data = get_document(url)

    # ANALYSIS
    description = data['results'][0]['analysis']
    misp.add_named_attribute(event, 'External analysis', 'comment', value=description, comment='Analysis')

    # MITIGATION
    try:
        mitigation = data['results'][0]['mitigation']
        misp.add_named_attribute(event, 'External analysis', 'comment', value=mitigation, comment='Mitigation')
    except KeyError:
        pass

    # THREAT TYPES
    for type in data['results'][0]['threat_types']:
        if type == 'Cyber Espionage':
            misp.add_tag(event, 'Threat Type: Cyber Espionage')
        if type == 'Cyber Crime':
            misp.add_domain(event, 'Threat Type: Cyber Crime')
        if type == 'Hacktivism':
            misp.add_tag(event, 'Threat Type: Hacktivism')
        if type == 'Vulnerability':
            misp.add_tag(event, 'Threat Type: Vulnerability')

    # ATTRIBUTES
    for indicators in data['results'][0]['links']:

        # COUNTRY
        if indicators['type'] == 'country':
            country = indicators['key']
            misp.add_named_attribute(event, 'Attribution', 'comment', country, comment='Country')   # Created Attribution
            country_url = keys.idef_base_url + indicators['href']
            region = get_region(country_url)
            tag = region + ':' + country        # Adds Tag
            misp.new_tag(tag,exportable=True)
            misp.add_tag(event, tag)

        # REGION
        if indicators['type'] == 'region':
            region = indicators['key']
            misp.add_named_attribute(event, 'Attribution', 'comment', region, comment='Region')
            misp.new_tag(region)
            misp.add_tag(event, region)

        # DETECTION_SIGNATURE (change up because of MISP YARA and SNORT)
        if indicators['type'] == 'detection_signature':
            detection_url = keys.idef_base_url + indicators['href']
            get_detection_signature(event, url=detection_url)

        # DOMAIN
        if indicators['type'] == 'domain':
            domain_url = keys.idef_base_url + indicators['href']
            get_domain(event, domain_url)

        # FILE
        if indicators['type'] == 'file':
            file = indicators['key']
            file_url = keys.idef_base_url + indicators['href']
            misp.add_hashes(event, md5=file, comment=get_file(event, url=file_url))

        # GLOBAL EVENT
        if indicators['type'] == 'global_event':
            global_url = keys.idef_base_url + indicators['href']
            get_global_event(event, global_url)

        # IP
        if indicators['type'] == 'ip':
            ip_url = keys.idef_base_url + indicators['href']
            get_ip(event, ip_url)

        # MALICIOUS EVENT




