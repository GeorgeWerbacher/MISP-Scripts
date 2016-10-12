from pymisp import PyMISP
import keys
from termcolor import colored
misp = PyMISP(keys.misp_url, keys.misp_key, False, 'json')


def search_events(case_name):
    search = misp.search_index(eventinfo=case_name)
    try:
        event_id = (search['response'][0]['id'])
        event_id = int(event_id.encode('utf8'))
        if event_id != {}:
            return event_id
    except IndexError:
        return


def create_event(data):
    case_name = data['title']
    print colored('Adding New Case: %s' % case_name, "yellow")
    event = misp.new_event(1, 4, 0, case_name)

    # Adds Threat Central Tag
    misp.add_tag(event, 'TruStar')

    # Adds Description, if any
    print('Adding Description.....')
    event_description = data['reportBody']
    misp.add_named_attribute(event, 'External analysis', "comment", value=event_description)

    # Adds Indicators
    indicators_in_case = data['indicators']
    print('Adding Indicators.....')
    for o in indicators_in_case:
        ind_value = o['value']
        ind_type = o['indicatorType']
        if ind_type == 'IP':
            misp.add_ipdst(event, ind_value)
            print("**** Added IP: %s" % ind_value)
        elif ind_type == 'URL':
            misp.add_domain(event, ind_value)
            print("**** Added URL: %s" % ind_value)
        elif ind_type == 'REGISTRY_KEY':
            misp.add_regkey(event, ind_value)
            print("**** Added REGISTRY_KEY: %s" % ind_value)
        elif ind_type == 'MUTEX':
            misp.add_mutex(event, ind_value)
            print("**** Added MUTEX: %s" % ind_value)
        elif ind_type == 'MD5':
            misp.add_hashes(event, md5=ind_value)
            print("**** Added MD5: %s" % ind_value)
        elif ind_type == 'SHA1':
            misp.add_hashes(event, sha1=ind_value)
            print("**** Added SHA1: %s" % ind_value)
        elif ind_type == 'SHA256':
            misp.add_hashes(event, sha256=ind_value)
            print("**** Added SHA256: %s" % ind_value)
        elif ind_type == 'SOFTWARE' or 'MALWARE':
            misp.add_filename(event, ind_value)
            print("**** Added FILENAME: %s" % ind_value)
        elif ind_type == 'EMAIL_ADDRESS':
            misp.add_email_src(event, ind_value)
            print("**** Added EMAIL: %s" % ind_value)
        else:
            print("Unsupported indicator type: %s" % ind_type)


"""
def update_event(event_id_num, data):
    print("Case Already Exists, Let's update it!")
    event = misp.get_event(event_id_num)

    # Adds Description, if any
    print('Adding Description.....')
    event_description = data['reportBody']
    misp.add_named_attribute(event, 'External analysis', "comment", value=event_description)

    # Adds Indicators
    indicators_in_case = data['indicators']
    print('Adding Indicators.....')
    for o in indicators_in_case:
        ind_value = o['value']
        ind_type = o['indicatorType']
        if ind_type == 'IP':
            misp.add_ipdst(event, ind_value)
            print("**** Added IP: %s" % ind_value)
        elif ind_type == 'URL':
            misp.add_domain(event, ind_value)
            print("**** Added URL: %s" % ind_value)
        elif ind_type == 'REGISTRY_KEY':
            misp.add_regkey(event, ind_value)
            print("**** Added REGISTRY_KEY: %s" % ind_value)
        elif ind_type == 'MUTEX':
            misp.add_mutex(event, ind_value)
            print("**** Added MUTEX: %s" % ind_value)
        elif ind_type == 'MD5':
            misp.add_hashes(event, md5=ind_value)
            print("**** Added MD5: %s" % ind_value)
        elif ind_type == 'SHA1':
            misp.add_hashes(event, sha1=ind_value)
            print("**** Added SHA1: %s" % ind_value)
        elif ind_type == 'SHA256':
            misp.add_hashes(event, sha256=ind_value)
            print("**** Added SHA256: %s" % ind_value)
        elif ind_type == 'SOFTWARE' or 'MALWARE':
            misp.add_filename(event, ind_value)
            print("**** Added FILENAME: %s" % ind_value)
        elif ind_type == 'EMAIL_ADDRESS':
            misp.add_email_src(event, ind_value)
            print("**** Added EMAIL: %s" % ind_value)
        else:
            print("Unsupported indicator type: %s" % ind_type)

    misp.update_event(event_id_num, event)
"""