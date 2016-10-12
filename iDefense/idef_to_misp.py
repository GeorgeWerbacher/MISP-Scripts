"""
Created by George Werbacher as part of the Acquia Cyber Defense Center

Description: The purpose of this script is to pull cases from ThreatCentral and import them into MISP
as an event. Cases that already exists will be updated to help eliminate duplicate entries.

Usage: python idef_case_to_misp.py -h

"""
import keys
import dateutil.parser
import idefense_export
from termcolor import colored


if __name__ == "__main__":
    for i in range(0, 5):
        document_url = 'https://api.intelgraph.verisign.com/rest/document/v0?page=%d&page_size=1' % i
        data = idefense_export.get_document(document_url)
        case_name = data['results'][0]['title']
        case_name = case_name.encode('utf8')
        case_date = dateutil.parser.parse(data['results'][0]['created_on'])
        case_date = case_date.strftime('%Y-%m-%d')
        print case_name

        try:
            if data['results'][0]['analysis'] is not None:
                print('Description')
                description = data['results'][0]['analysis']
        except KeyError:
            print 'No Description included'
            pass

        try:
            if data['content'][0]['mitigation'] is not None:
                print('Mitigation')
                mitigation = data['results'][0]['mitigation']
        except KeyError:
            print 'No mitigation strategies included'
            pass

        # Let's find those attributes
        for indicators in data['results'][0]['links']:

            # VULNERABILITY (attribute)
            if indicators['type'] == 'vulnerability':
                vulnerability = indicators['key']
                print colored(vulnerability, 'green')

            # VULNERABILITY TECH (no attribute)
            elif indicators['type'] == 'vuln_tech':
                vuln_tech = indicators['key']
                print vuln_tech

            # PACKAGE (no attribute)
            elif indicators['type'] == 'package':
                package = indicators['key']
                print package

            # DETECTION SIGNATURE (no attribute - yara)
            elif indicators['type'] == 'dectection_signature':
                detection_signature = indicators['key']
                print detection_signature

            # FILE (attribute MD5, SHA1, SHA256, Filename)
            elif indicators['type'] == 'file':
                file_url = indicators['href']
                url = keys.idef_base_url + file_url
                hash = idefense_export.get_file(url)
                print colored(hash, color='red')

            # PHISH (attribute - email-src)
            elif indicators['type'] == 'phish':
                phish = indicators['key']
                print 'Phishing Campaign'
                print phish

            # MALWARE FAMILY (no attribute)
            elif indicators['type'] == 'malware_family':
                malware_family = indicators['key']
                print malware_family

            # MALICIOUS TOOL (no attribute)
            elif indicators['type'] == 'malicious_tool':
                malicious_tool = indicators['key']
                print malicious_tool

            # DOMAIN (attribute - domain)
            elif indicators['type'] == 'domain':
                domain = indicators['key']
                print domain

            # IP ADDRESS (attribute - ip-dst)
            elif indicators['type'] == 'ip':
                ip = indicators['key']
                print ip

            # ASN (no attribute)
            elif indicators['type'] == 'asn':
                asn = indicators['key']
                print asn

            # URL (attribute - url)
            elif indicators['type'] == 'url':
                url = indicators['key']
                print colored(url, 'yellow')

            # THREAT GROUP (attribute - Threat actor w/ tag)
            elif indicators['type'] == 'threat_group':
                threat_group = indicators['key']
                print threat_group

            # THREAT ACTOR (attribute - Threat actor w/o tag)
            elif indicators['type'] == 'threat_actor':
                actor = indicators['key']
                print colored(actor, 'blue')

            # MALICIOUS EVENT (no attribute)
            elif indicators['type'] == 'malicious_activity':
                malicious_event = indicators['key']
                print malicious_event

            # THREAT CAMPAIGN (attribute - campaign)
            elif indicators['type'] == 'threat_campaign':
                threat_campaign = indicators['key']
                print threat_campaign

            # TARGET ORGANIZATION (attribute - target-external)
            elif indicators['type'] == 'target_organization':
                target_organization = indicators['key']
                print target_organization

            # GLOBAL EVENT (no attribute)
            elif indicators['type'] == 'global_event':
                global_event = indicators['key']
                print global_event

            # COUNTRY (no attribute)
            elif indicators['type'] == 'country':
                country = indicators['key']
                print country

            # REGION (no attribute)
            elif indicators['type'] == 'region':
                region = indicators['key']
                print 'Region: %s' % region

            # VERTICAL
            elif indicators['type'] == 'vertical':
                vertical = indicators['key']
                print vertical

            else:
                print 'File type not supported.....booooo'

