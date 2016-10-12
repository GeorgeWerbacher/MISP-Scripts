"""
Created by George Werbacher as part of the Acquia Cyber Defense Center

Description: The purpose of this script is to pull cases from ThreatCentral and import them into MISP
as an event. Cases that already exists will be updated to help eliminate duplicate entries.

Usage: python tc_case_to_misp.py -h

"""
import argparse
import dateutil.parser
import requests
from pymisp import PyMISP
from termcolor import colored
import keys
from misp_import import create_event, create_actor, update_event, update_actor, search_events, publish_event

misp = PyMISP(keys.misp_url, keys.misp_key, False, 'json')


def grab_total_cases():
    try:
        for i in range(570, 999):
            total = i
            url = 'https://threatcentral.io/tc/rest/summaries?entities=cases&page=%d&size=1' % i
            r = requests.get(url, auth=(keys.tc_user, keys.tc_pass))
            if r.status_code != 200:
                print('Status:', r.status_code, 'Problem with the connection to Case API. Exiting...')
            data = r.json()
            case_name = data['content'][0]['resource']['title']
    except IndexError:
        return total - 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Pull from ThreatCentral and Upload to MISP')
    parser.add_argument("-c", "--cases", help='Specify number of cases to upload (int value or all)')
    parser.add_argument("-a", "--actors", help='Specify number of actors to upload (int value or all)')
    parser.add_argument("-v", "--verbose", help='Increase output verbosity', action="store_true")
    args = parser.parse_args()

    if args.cases == 'all':
        total = grab_total_cases()
        for i in range(0, total):
            print colored('Case %d of %d' % (i + 1, total), 'red')
            try:
                url = 'https://threatcentral.io/tc/rest/summaries?entities=cases&page=%d&size=1' % i
                r = requests.get(url, auth=(keys.tc_user, keys.tc_pass))
                if r.status_code != 200:
                    print('Status:', r.status_code, 'Problem with the connection to Case API. Exiting...')
                data = r.json()
                case_name = data['content'][0]['resource']['title']
                case_name = case_name.encode('utf8')
                case_date = dateutil.parser.parse(data['content'][0]['resource']['createDate'])
                case_date = case_date.strftime('%Y-%m-%d')

                if search_events(case_name=case_name) is not None:
                    event_id_num = search_events(case_name=case_name)
                    update_event(event_id_num=event_id_num, data=data)
                    publish_event(event_id_num=event_id_num)
                    print 'Event already exists...'
                else:
                    create_event(case_name=case_name, case_date=case_date, data=data)
            except IndexError:
                print ('Upload complete! Have a beer')
                break
    if args.cases:
        total = int(args.cases)
        for i in range(0, total):
            print colored('Case %d of %d' % (i + 1, total), 'red')
            try:
                url = 'https://threatcentral.io/tc/rest/summaries?entities=cases&page=%d&size=1' % i
                r = requests.get(url, auth=(keys.tc_user, keys.tc_pass))
                if r.status_code != 200:
                    print('Status:', r.status_code, 'Problem with the connection to Case API. Exiting...')
                data = r.json()
                case_name = data['content'][0]['resource']['title']
                case_name = case_name.encode('utf8')
                case_date = dateutil.parser.parse(data['content'][0]['resource']['createDate'])
                case_date = case_date.strftime('%Y-%m-%d')

                if search_events(case_name=case_name) is not None:
                    event_id_num = search_events(case_name=case_name)
                    if event_id_num == 160:
                        print 'This is the huge event that I am going to skip'
                    else:
                        update_event(event_id_num=event_id_num, data=data)
                        publish_event(event_id_num=event_id_num)
                else:
                    create_event(case_name=case_name, case_date=case_date, data=data)
            except IndexError:
                print ('Upload complete! Have a beer')
                break
    if args.actors == 'all':
        total = grab_total_cases()
        for i in range(0, total):
            print colored('Actor %d of %d' % (i + 1, total), 'green')
            try:
                url = 'https://threatcentral.io/tc/rest/summaries?entities=actors&page=%d&size=1' % i
                r = requests.get(url, auth=(keys.tc_user, keys.tc_pass))
                if r.status_code != 200:
                    print('Status:', r.status_code, 'Problem with the connection to Case API. Exiting...')
                data = r.json()
                actor_name = data['content'][0]['resource']['name']
                actor_name = actor_name.encode('utf8')
                actor_date = dateutil.parser.parse(data['content'][0]['resource']['createDate'])
                actor_date = actor_date.strftime('%Y-%m-%d')

                if search_events(case_name=actor_name) is not None:
                    event_id_num = search_events(case_name=actor_name)
                    update_actor(event_id_num=event_id_num, data=data)
                    publish_event(event_id_num=event_id_num)
                else:
                    create_actor(actor_name=actor_name, actor_date=actor_date, data=data)
            except IndexError:
                print ('Upload complete! Have a beer')
                break
    if args.actors:
        total = int(args.actors)
        for i in range(0, total):
            print colored('Actor %d of %d' % (i + 1, total), 'green')
            try:
                url = 'https://threatcentral.io/tc/rest/summaries?entities=actors&page=%d&size=1' % i
                r = requests.get(url, auth=(keys.tc_user, keys.tc_pass))
                if r.status_code != 200:
                    print('Status:', r.status_code, 'Problem with the connection to Case API. Exiting...')
                data = r.json()
                actor_name = data['content'][0]['resource']['name']
                actor_name = actor_name.encode('utf8')
                actor_date = dateutil.parser.parse(data['content'][0]['resource']['createDate'])
                actor_date = actor_date.strftime('%Y-%m-%d')

                if search_events(case_name=actor_name) is not None:
                    event_id_num = search_events(case_name=actor_name)
                    update_actor(event_id_num=event_id_num, data=data)
                    publish_event(event_id_num=event_id_num)
                else:
                    create_actor(actor_name=actor_name, actor_date=actor_date, data=data)
            except IndexError:
                print ('Upload complete! Have a beer')
                break
