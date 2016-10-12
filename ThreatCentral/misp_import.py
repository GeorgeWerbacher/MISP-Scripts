from pymisp import PyMISP
import keys

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


def create_event(case_name, case_date, data):
    event = misp.new_event(1, 4, 0, case_name, case_date)

    # Adds Threat Actor + Tag, if any
    if data['content'][0]['resource']['actors'] is not None:
        print('Adding Threat Actors.....')
        for actors in data['content'][0]['resource']['actors']:
            threats_actor = actors['name']
            if actors.has_key('description'):
                description = actors['description']
                misp.add_threat_actor(event, threats_actor, comment=description)
            else:
                misp.add_threat_actor(event, threats_actor)

    # Adds Description, if any
    try:
        if data['content'][0]['resource']['description'] is not None:
            print('Adding Description.....')
            event_description = data['content'][0]['resource']['description']
            misp.add_named_attribute(event, 'External analysis', "comment", value=event_description)
    except KeyError:
            pass

    # Adds Indicators
    indicators_in_case = data['content'][0]['resource']['indicators']
    print('Adding Indicators.....')
    for i in indicators_in_case:
        observable_count = i['observables']
        for o in observable_count:
            ind_value = o['value']
            ind_type = o['type']['value']
            if ind_type == 'IP':
                misp.add_ipdst(event, ind_value)
                print("**** Added IP: %s" % ind_value)
            elif ind_type == 'URI':
                misp.add_url(event, ind_value)
                print("**** Added URL: %s" % ind_value)
            elif ind_type == 'DOMAIN':
                misp.add_domain(event, ind_value)
                print("**** Added DOMAIN: %s" % ind_value)
            elif ind_type == 'REGISTRY_KEY':
                misp.add_regkey(event, ind_value)
                print("**** Added REGISTRY_KEY: %s" % ind_value)
            elif ind_type == 'MUTEX':
                misp.add_mutex(event, ind_value)
                print("**** Added MUTEX: %s" % ind_value)
            elif ind_type == 'FILE_HASH':
                hash_type = o['fileHashes'][0]['type']
                hash_value = o['fileHashes'][0]['value']
                if hash_type == 'MD5':
                    misp.add_hashes(event, md5=hash_value)
                    print("**** Added MD5: %s" % ind_value)
                elif hash_type == 'SHA1':
                    misp.add_hashes(event, sha1=hash_value)
                    print("**** Added SHA1: %s" % ind_value)
                elif hash_type == 'SHA256':
                    misp.add_hashes(event, sha256=hash_value)
                    print("**** Added SHA256: %s" % ind_value)
            else:
                print("Unsupported indicator type: %s" % ind_type)


def update_event(event_id_num, data):
    print("Case Already Exists, Let's update it!")
    case = misp.get_event(event_id_num)
    event = case

    # Adds Threat Actor + Tag, if any
    if data['content'][0]['resource']['actors'] is not None:
        print('Adding Threat Actors.....')
        for actors in data['content'][0]['resource']['actors']:
            threats_actor = actors['name']
            if actors.has_key('description'):
                description = actors['description']
                misp.add_threat_actor(event, threats_actor, comment=description)
            else:
                misp.add_threat_actor(event, threats_actor)

    # Adds Description, if any
    try:
        if data['content'][0]['resource']['description'] is not None:
            print('Adding Description.....')
            event_description = data['content'][0]['resource']['description']
            misp.add_named_attribute(event, 'External analysis', "comment", value=event_description)
    except KeyError:
            pass

    print('Updating Indicators.....')
    indicators_in_case = data['content'][0]['resource']['indicators']
    for i in indicators_in_case:
        observable_count = i['observables']
        for o in observable_count:
            ind_value = o['value']
            ind_type = o['type']['value']
            if ind_type == 'IP':
                misp.add_ipdst(event, ind_value)
            elif ind_type == 'URI':
                misp.add_url(event, ind_value)
            elif ind_type == 'DOMAIN':
                misp.add_domain(event, ind_value)
            elif ind_type == 'REGISTRY_KEY':
                misp.add_regkey(event, ind_value)
            elif ind_type == 'MUTEX':
                misp.add_mutex(event, ind_value)
            elif ind_type == 'FILE_HASH':
                hash_type = o['fileHashes'][0]['type']
                hash_value = o['fileHashes'][0]['value']
                if hash_type == 'MD5':
                    misp.add_hashes(event, md5=hash_value)
                elif hash_type == 'SHA1':
                    misp.add_hashes(event, sha1=hash_value)
                elif hash_type == 'SHA256':
                    misp.add_hashes(event, sha256=hash_value)
            else:
                print("Unsupported indicator type: %s" % ind_type)
    misp.update_event(event_id_num, event)


def publish_event(event_id_num):
    print 'Publishing the Event...'
    event = misp.get_event(event_id_num)
    misp.publish(event)


def create_actor(actor_name, actor_date, data):

    event = misp.new_event(1, 4, 0, info='Threat Actor: %s' % actor_name, date=actor_date)
    misp.add_threat_actor(event, actor_name)

    # Adds Threat Actor + Tag, if any
    if data['content'][0]['resource']['actors'] is not None:
        misp.add_tag(event, 'Threat Actor')
        print('Adding Threat Actors.....')
        for actors in data['content'][0]['resource']['actors']:
            threats_actor = actors['name']
            if actors.has_key('description'):
                description = actors['description']
                misp.add_threat_actor(event, threats_actor, comment=description)
            else:
                misp.add_threat_actor(event, threats_actor)

    # Adds Description, if any
    try:
        if data['content'][0]['resource']['description'] is not None:
            print('Adding Description.....')
            event_description = data['content'][0]['resource']['description']
            misp.add_named_attribute(event, 'External analysis', "comment", value=event_description)
    except KeyError:
            pass

    # Adds TTPs, if any
    try:
        if data['content'][0]['resource']['tacticsTechniquesAndProcedures'] is not None:
            for ttps in data['content'][0]['resource']['tacticsTechniquesAndProcedures']:
                ttp = ttps['description']
                misp.add_internal_text(event, ttp, comment="Tools, Tactics, and Procedures")
    except KeyError:
            pass

    # Adds Motivation, if any
    if data['content'][0]['resource']['motivations'] is not None:
        for mot in data['content'][0]['resource']['motivations']:
            motivation = mot['displayName']
            misp.add_internal_text(event, motivation, comment="Motivation")

    # Adds Intended Effects, if any
    if data['content'][0]['resource']['intendedEffects'] is not None:
        for eff in data['content'][0]['resource']['intendedEffects']:
            effects = eff['displayName']
            misp.add_internal_text(event, effects, comment="Intended Effects")


def update_actor(event_id_num, data):
    print("Actor Already Exists, Let's update it!")
    case = misp.get_event(event_id_num)
    event = case

    # Adds Threat Actor + Tag, if any
    if data['content'][0]['resource']['actors'] is not None:
        print('Adding Threat Actors.....')
        for actors in data['content'][0]['resource']['actors']:
            threats_actor = actors['name']
            misp.add_tag(event, 'Threat Actor')
            if actors.has_key('description'):
                description = actors['description']
                misp.add_threat_actor(event, threats_actor, comment=description)
            else:
                misp.add_threat_actor(event, threats_actor)

    # Adds Description, if any
    try:
        if data['content'][0]['resource']['description'] is not None:
            print('Adding Description.....')
            event_description = data['content'][0]['resource']['description']
            misp.add_named_attribute(event, 'External analysis', "comment", value=event_description)
    except KeyError:
            pass

    # Adds TTPs, if any
    try:
        if data['content'][0]['resource']['tacticsTechniquesAndProcedures'] is not None:
            for ttps in data['content'][0]['resource']['tacticsTechniquesAndProcedures']:
                ttp = ttps['description']
                misp.add_internal_text(event, ttp, comment="Tools, Tactics, and Procedures")
    except KeyError:
            pass

    # Adds Motivation, if any
    if data['content'][0]['resource']['motivations'] is not None:
        for mot in data['content'][0]['resource']['motivations']:
            motivation = mot['displayName']
            misp.add_internal_text(event, motivation, comment="Motivation")

    # Adds Intended Effects, if any
    if data['content'][0]['resource']['intendedEffects'] is not None:
        for eff in data['content'][0]['resource']['intendedEffects']:
            effects = eff['displayName']
            misp.add_internal_text(event, effects, comment="Intended Effects")

    misp.update_event(event_id_num, event)