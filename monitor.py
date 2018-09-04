from pymongo import MongoClient
import requests
from time import gmtime, strftime
import json
import re
import sys
requests.packages.urllib3.disable_warnings()

#mongo settings
try:
    client = MongoClient('localhost:27017')
    db = client.certs
except Exception as e:
    print "Mongo Connect Error"
    print str(e)
    sys.exit()

# Config
API_URL = "https://www.censys.io/api/v1"
theconfig = db.config.find_one({})
UID = theconfig['censys_uid']
SECRET = theconfig['censys_secret']
if UID == '' or SECRET == '':
    print "Please set Censys API info"
    sys.exit()


def censys_cert(hash):
    query = {'query': '{s}'.format(s=hash), 'fields': [
        'ip', 'updated_at', '443.https.tls.certificate.parsed.fingerprint_sha1',
        '443.https.tls.certificate.parsed.issuer_dn', '443.https.tls.certificate.parsed.subject_dn',
        '443.https.tls.certificate.parsed.validity.start', '443.https.tls.certificate.parsed.validity.end',
        '443.https.ssl_2.certificate.parsed.validity.end', '443.https.ssl_2.certificate.parsed.validity.start',
        '443.https.ssl_2.certificate.parsed.subject_dn', '443.https.ssl_2.certificate.parsed.issuer_dn'],
        'flatten': True}
    r = requests.post(API_URL + "/search/ipv4", data=json.dumps(query) , auth=(UID, SECRET))
    if r.status_code != 200:
        print "Error: " + str(r.status_code)
        pass
    else:    
        thejson = r.json()
        if (thejson['status'] == 'ok'):
            for ips in thejson['results']:
                theip = ips['ip']
                checker = db.monitor.find({'$and': [{'indicator':hash},{'passive':theip}]})
                if  checker.count() > 0:
                    #Passive Info already Exists
                    pass
                else:
                    print "Censys Adding: " + theip
                    db.monitor.update({'indicator':hash},{'$addToSet':{'passive': theip}})
                    createAlert(hash,theip)

def censys_ip(ip):
    query = {'query': 'ip: {ip}'.format(ip=ip), 'fields': ['443.https.tls.certificate.parsed.fingerprint_sha1',
                '443.https.tls.certificate.parsed.issuer_dn',
                '443.https.tls.certificate.parsed.subject_dn',
                'updated_at',
                '443.https.ssl_2.certificate.parsed.fingerprint_sha1',
                '443.https.ssl_2.certificate.parsed.issuer_dn',
                '443.https.ssl_2.certificate.parsed.subject_dn'],
                'flatten': True}
    r = requests.post(API_URL + "/search/ipv4", data=json.dumps(query) , auth=(UID, SECRET))
    if r.status_code != 200:
        print "Error: " + str(r.status_code)
        pass
    else:    
        thejson = r.json()
        if (thejson['status'] == 'ok'):
            for certs in thejson['results']:
                if '443.https.tls.certificate.parsed.fingerprint_sha1' in certs : 
                    thessl = certs['443.https.tls.certificate.parsed.fingerprint_sha1']
                    checker = db.monitor.find({'$and': [{'indicator':ip},{'passive':thessl}]})
                    if  checker.count() > 0:
                        #Passive Info already Exists
                        pass
                    else:
                        print "Censys Adding: " + thessl
                        db.monitor.update({'indicator':ip},{'$addToSet':{'passive': thessl}})
                        createAlert(ip,thessl)
                    
        
def createAlert(indy,data):
    print "Creating DB Alert"
    thedate = strftime("%Y-%m-%d %H:%M", gmtime())
    db.monitor.update({'indicator':indy},{'$set':{'alert': True}})
    db.monitor.update({'indicator':indy},{'$set':{'last_alert': thedate}})
    db.monitor.update({'indicator':indy},{'$addToSet':{'alerts': {"value":data,"date":thedate}}})

    print "Creating Json Alert"
    thedata = {}
    thedata['indicator'] = indy
    thedata['alerts'] = {"value":data,"date":thedate}

    with open("alerts.log", "a") as outfile:
        outfile.write(json.dumps(thedata))
        outfile.write("\n")
        outfile.close()


# Get Monitor List
monitors = db.monitor.find({'monitor': True})
thecount = monitors.count()
if thecount == 0:
    print "No items to monitor"
else:
    for mons in monitors:
        indy = mons['indicator']
        thedate = strftime("%Y-%m-%d %H:%M", gmtime())
        if mons['indicator_type'] == "Cert":
            censys_cert(indy)
            db.monitor.update({'indicator':indy},{'$set':{'last_checked': thedate}})
        if mons['indicator_type'] == "IP":
            censys_ip(indy)
            db.monitor.update({'indicator':indy},{'$set':{'last_checked': thedate}})
