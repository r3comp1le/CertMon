from app import app
from flask import Flask, render_template, flash, request, jsonify, redirect
from pymongo import MongoClient
import datetime
import requests
import logging
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# create a file handler
handler = logging.FileHandler('debug.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

#mongo settings
try:
    client = MongoClient('localhost:27017')
    db = client.certs
except Exception as e:
        logger.error(str(e))

@app.route('/')
@app.route('/index')
def index():
    results = db.monitor.find({'alert':True})
    if results.count() == 0:
        clean = True
    else:
        clean = False

    # Account Info
    theconfig = db.config.find_one({})
    if theconfig != None :
        if len(theconfig['censys_uid']) > 1:
            url = "https://censys.io/api/v1/account"
            UID = theconfig['censys_uid']
            SECRET = theconfig['censys_secret']
            r = requests.get(url, auth=(UID, SECRET))
            if r.status_code == 200:
                account_info =  r.json()
                return render_template('index.html', title="Home", results=results,clean=clean,account_info=account_info)

    return render_template('index.html', title="Home", results=results,clean=clean)

@app.route('/monitor')
def monitor():
    theindicators = db.monitor.find({})
    return render_template('monitor.html', title="Monitor", indicators=theindicators)

@app.route('/view_alert', methods=['GET'])
def view_alert():
    if request.args['indy']:
        indy = request.args['indy']
        theindy = db.monitor.find({'indicator':indy})
        if theindy.count() > 0:
            for alerts in theindy:
                alerts = alerts['alerts']
            return render_template('alerts.html', title="Alert", alerts=alerts, indicator=indy)
    
    return render_template('alerts.html', title="Alert", indicator=indy)

@app.route('/view_indicator', methods=['GET'])
def view_indicator():
    if request.args['indy']:
        indy = request.args['indy']
        indy_type = request.args['type']
        theindy = db.monitor.find({'indicator':indy})
        if theindy.count() > 0:
            for items in theindy:
                passivedate = items['passive']
                thenote = items['note']
            return render_template('indicator.html', title="Indicator", passive=passivedate, indicator=indy, type=indy_type, note=thenote)
            
    return render_template('indicator.html', title="Indicator", indicator=indy, type=indy_type)

@app.route('/arch_alert', methods=['POST'])
def arch_alert():
    if request.form['id']:
        id = request.form['id']
        db.monitor.find_one_and_update({'indicator' : id},{'$set' : {'alert': False}})
        db.monitor.find_one_and_update({'indicator' : id},{'$set' : {'alerts': []}})
        return redirect('/') 

@app.route('/add_indy', methods=['POST'])
def add_indy():
    try:
        logger.info('Adding Monitor')

        theindy = request.form['indy']
        thenote = request.form['note']
        now = datetime.datetime.now()
        thedate = now.strftime("%Y-%m-%d %H:%M")
        
        try:
            socket.inet_aton(theindy)
            indy_type = "IP"
        except socket.error:
            indy_type = "Cert"

        db.monitor.insert({
            'indicator':theindy,
            'indicator_type':indy_type,
            'alert':False,
            'added':thedate,
            'last_checked':'',
            'last_alert':'',
            'note':thenote,
            'monitor':True,
            'passive':[]})

    except Exception as e:
        logger.error(str(e))  

    return redirect('monitor') 

@app.route('/del_indy', methods=['POST'])
def del_indy():
    try:
        logger.info('Delete Monitor')

        theindy = request.form['id']
        db.monitor.delete_one({
            'indicator':theindy})

    except Exception as e:
        logger.error(str(e))  

    return redirect('monitor') 

@app.route('/edit_note', methods=['POST'])
def edit_note():
    try:
        logger.info('Editing Notes')

        thenote = request.form['note']
        indicator = request.form['indicator']
        db.monitor.find_one_and_update({'indicator' : indicator},{'$set' : {'note': thenote}})

    except Exception as e:
        logger.error(str(e))  

    return redirect('monitor') 
    
@app.route('/config')
def config():
    theconfig = db.config.find_one({})
    if theconfig == None:
        logger.info('Config Does Not Exists')
        db.config.insert({'theid':'1234567890','censys_uid':"",'censys_secret':""})
        theconfig = db.config.find_one({})
        client.close()
    else: 
        logger.info('Config Exists')

    return render_template('config.html', title="Config", config=theconfig)

@app.route('/add_to_config', methods=['POST'])
def add_to_config():
    try:
        logger.info('Modifying Config')

        the_uid = request.form['censys_uid']
        the_secret = request.form['censys_secret']

        logger.info('Saving Config')
        db.config.update({'theid':'1234567890'},{'theid':'1234567890','censys_uid':the_uid,'censys_secret':the_secret}, upsert=False)

        return redirect('config')

    except Exception as e:
        logger.error(str(e))  

@app.errorhandler(500)
def internal_error(error):
    logger.info('500 Error')
    return render_template('error.html', error=error)

@app.errorhandler(404)
def not_found(error):
    logger.info('404 Error')
    return render_template('error.html', error='404')
