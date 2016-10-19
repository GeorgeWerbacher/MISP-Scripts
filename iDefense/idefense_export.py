import requests
import keys
import dateutil.parser
import json
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


def get_attributes(indicators, event):
    # COUNTRY
    if indicators['type'] == 'country':
        country = indicators['key']
        misp.add_named_attribute(event, 'Attribution', 'comment', country, comment='Country')  # Created Attribution
        country_url = keys.idef_base_url + indicators['href']
        region = get_region(country_url)
        tag = region + ':' + country  # Adds Tag
        misp.new_tag(tag, exportable=True)
        misp.add_tag(event, tag)

    # REGION
    if indicators['type'] == 'region':
        region = indicators['key']
        misp.add_named_attribute(event, 'Attribution', 'comment', region, comment='Region')
        misp.new_tag(region)
        misp.add_tag(event, region)

    # DETECTION_SIGNATURE
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
    if indicators['type'] == 'malicious_event':
        print 'Getting Malicious Event'
        event_url = keys.idef_base_url + indicators['href']
        print event_url
        import_malicious_event(event_url)

    # THREAT ACTOR
    if indicators['type'] == 'threat_actor':
        actor_url = keys.idef_base_url + indicators['href']
        print actor_url
        misp.add_threat_actor(event, target=indicators['key'])
        import_threat_actor(actor_url)


def search_events(case_name):
    search = misp.search_index(eventinfo=case_name)
    try:
        event_id = (search['response'][0]['id'])
        event_id = int(event_id.encode('utf8'))
        if event_id != {}:
            return event_id
    except IndexError:
        return


def import_threat_actor(url):
    data = get_document(url)

    event_name = data['key']
    event_name = event_name.encode('utf8')
    event_date = dateutil.parser.parse(data['created_on'])
    event_date = event_date.strftime('%Y-%m-%d')

    if search_events(event_name) is not None:
        print 'Actor Already Exists..'
    else:
        event = misp.new_event(1, 4, 0, info='Threat Actor: %s' % event_name, date=event_date)

        # DESCRIPTION
        try:
            description = data['description']
            misp.add_named_attribute(event, 'External analysis', 'comment', value=description, comment='Description')
        except KeyError:
            pass

        # ANALYSIS
        try:
            analysis = data['analysis']
            misp.add_named_attribute(event, 'External analysis', 'comment', value=analysis, comment='Analysis')
        except KeyError:
            pass

        # CAPABILITIES
        try:
            misp.add_named_attribute(event, 'External analysis', 'comment', value=data['capabilities'], comment='Capabilities')
        except KeyError:
            pass

        # SOURCES
        try:
            for sources in data['sources_external']:
                misp.add_named_attribute(event, 'External analysis', 'link', value=sources['url'], comment=sources['description'])
        except KeyError:
            pass

        # THREAT TYPES
        try:
            for type in data['threat_types']:
                if type == 'Cyber Espionage':
                    misp.add_tag(event, 'Threat Type: Cyber Espionage')
                    print 'Added Tag - Esp'
                elif type == 'Cyber Crime':
                    misp.add_domain(event, 'Threat Type: Cyber Crime')
                    print 'Added Tag - Crime'
                elif type == 'Hacktivism':
                    misp.add_tag(event, 'Threat Type: Hacktivism')
                    print 'Added Tag - Hack'
                elif type == 'Vulnerability':
                    misp.add_tag(event, 'Threat Type: Vulnerability')
                else:
                    print 'No Threat Types'
        except KeyError:
            pass

        # SKILL LEVEL
        try:
            misp.add_named_attribute(event, 'External analysis', 'comment', value=data['skill_lvl'], comment='Skill Level')
        except KeyError:
            pass

        # TTPs
        try:
            for ttp in data['ttps']:
                misp.add_named_attribute(event, 'External analysis', 'comment', value=ttp, comment='TTP')
        except KeyError:
            pass

        # REAL NAME
        try:
            misp.add_named_attribute(event, 'External analysis', 'text', value=data['real_name'], comment='Real Name')
        except KeyError:
            pass

        # ALIAS
        try:
            for attributes in data['links']:
                if attributes['relationship'] == 'alias':
                    misp.add_threat_actor(event, target=attributes['key'], comment='Alias')
        except KeyError:
            pass

        # ADDITIONIAL ATTRIBUTES
        try:
            for indicators in data['results'][0]['links']:
                get_attributes(indicators, event)
        except KeyError:
            pass

        # ADDS THREAT ACTOR ATTRIBUTE
        misp.add_threat_actor(event, target=event_name)
        misp.add_tag(event, tag='Threat Actor')


def import_malicious_event(url):
    data = get_document(url)

    event_name = data['title']
    event_name = event_name.encode('utf8')
    event_date = dateutil.parser.parse(data['created_on'])
    event_date = event_date.strftime('%Y-%m-%d')

    if search_events(event_name) is not None:
        print 'Case already exists'
    else:
        event = misp.new_event(1, 4, 0, info=event_name, date=event_date)
        # DESCRIPTION
        description = data['description']
        misp.add_named_attribute(event, 'External analysis', 'comment', value=description, comment='Description')

        '''
        # HASHTAGS
        try:
            for hashtag in data['hashtags']:
                misp.add_named_attribute(event, 'External analysis', 'link',
                                     value='https://twitter.com/hashtag/%s?src=hash' % hashtag, comment='Hashtag: %s' % hashtag)
        except KeyError:
            pass
        '''

        # THREAT TYPES (Not working for some reason)
        for type in data['threat_types']:
            if type == 'Cyber Espionage':
                misp.add_tag(event, 'Threat Type: Cyber Espionage')
                print 'Added Tag - Esp'
            elif type == 'Cyber Crime':
                misp.add_domain(event, 'Threat Type: Cyber Crime')
                print 'Added Tag - Crime'
            elif type == 'Hacktivism':
                misp.add_tag(event, 'Threat Type: Hacktivism')
                print 'Added Tag - Hack'
            elif type == 'Vulnerability':
                misp.add_tag(event, 'Threat Type: Vulnerability')
            else:
                print 'No Threat Types'

        # ATTRIBUTES
        print 'Attributes'
        for indicators in data['links']:
            get_attributes(indicators, event)

        misp.add_tag(event, tag='Malicious Event')


def import_intelligence_alert(url, case_name, case_date):
    if search_events(case_name) is not None:
        print 'Event already exists'
    else:
        event = misp.new_event(1, 4, 0, info='Intelligence Alert: %s' % case_name, date=case_date)
        data = get_document(url)

        # ANALYSIS
        misp.add_named_attribute(event, 'External analysis', 'comment', value=data['results'][0]['analysis'], comment='Analysis')

        # MITIGATION
        try:
            misp.add_named_attribute(event, 'External analysis', 'comment', value=data['results'][0]['mitigation'], comment='Mitigation')
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
        try:
            for indicators in data['results'][0]['links']:
                get_attributes(indicators, event)
        except KeyError:
            pass

        misp.add_tag(event, tag='Intelligence Alert')



