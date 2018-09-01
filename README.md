# CertMon
### Monitor Censys Data
Monitor SSL certificates by hash and IP addresses via Censys data.  Keep a record of findings and alert on new items.

### Setup
Make sure Mongo is running

pip install
```
requests
flask
pymongo
```

Start web server
```
cd CertMon/
flask run 
```
OR
```
python -m flask run
```

Visit http://localhost:5000/config and set Censys creds

### Monitor
Run `monitor.py` on desired interval to start querying Censys data

### FYI
* debug.log - Log of behaviour
* alert.log - Ingest into something like splunk
* API quota will display at the bottom of the main page
* SSL certs need to be SHA1

### ScreenShots

<kbd>![config](https://i.imgur.com/JtYEHhT.png "Config")</kbd>
Set creds

<kbd>![list](https://i.imgur.com/Gute6tl.png "List")</kbd>
List current items being monitored

<kbd>![add](https://i.imgur.com/HTrRQa7.png "Add")</kbd>
Add a new item with a note

<kbd>![data](https://i.imgur.com/UCQDPB0.png "Data")</kbd>
View findings

<kbd>![alert](https://i.imgur.com/6zBr8Jg.png "Alert")</kbd>
Show active alerts

<kbd>![details](https://i.imgur.com/I04kK2i.png "Details")</kbd>
Alert findings
