"""
Created by George Werbacher as part of the Acquia Cyber Defense Center

Description: The purpose of this script is to pull cases from ThreatCentral and import them into MISP
as an event. Cases that already exists will be updated to help eliminate duplicate entries.

Usage: python idef_case_to_misp.py -h

"""
import dateutil.parser
from termcolor import colored
import idefense_export

document_url = 'https://api.intelgraph.verisign.com/rest/document/v0/intelligence_alert?page=202&page_size=1'
data = idefense_export.get_document(document_url)
data = idefense_export.get_document(document_url)
case_name = data['results'][0]['title']
case_name = case_name.encode('utf8')
case_date = dateutil.parser.parse(data['results'][0]['created_on'])
case_date = case_date.strftime('%Y-%m-%d')
print colored(case_name, 'red')
idefense_export.import_intelligence_alert(document_url, case_name, case_date)


'''
if __name__ == "__main__":
    for i in range(0, 1):
        document_url = 'https://api.intelgraph.verisign.com/rest/document/v0?page=%d&page_size=1' % i
        data = idefense_export.get_document(document_url)
        case_name = data['results'][0]['title']
        case_name = case_name.encode('utf8')
        case_date = dateutil.parser.parse(data['results'][0]['created_on'])
        case_date = case_date.strftime('%Y-%m-%d')
        print case_name
'''