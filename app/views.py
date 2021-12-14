# Licensed Materials - Property of IBM
# 5725I71-CC011829
# (C) Copyright IBM Corp. 2015, 2020. All Rights Reserved.
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.

from flask import Blueprint, render_template, current_app, send_from_directory, request
from qpylib import qpylib

from flask import Response
from qpylib.qpylib import log
from qpylib.offense_qpylib import get_offense_json_html
import json
from qpylib.ariel import ArielSearch, ArielError

# pylint: disable=invalid-name
viewsbp = Blueprint('viewsbp', __name__, url_prefix='/')

# A simple "Hello" endpoint that demonstrates use of render_template
# and qpylib logging.
@viewsbp.route('/')
@viewsbp.route('/<name>')
def hello(name=None):
    qpylib.log('name={0}'.format(name), level='INFO')
    return render_template('hello.html', name=name)

# The presence of this endpoint avoids a Flask error being logged when a browser
# makes a favicon.ico request. It demonstrates use of send_from_directory
# and current_app.
@viewsbp.route('/favicon.ico')
def favicon():
    return send_from_directory(current_app.static_folder, 'favicon-16x16.png')


@viewsbp.route('/mitreinfo/<offense_id>', methods=['GET'])
def get_offense(offense_id):
    try:
        offense_json = get_offense_json_html(offense_id, custom_html_generator)
        return Response(response=offense_json, status=200, mimetype='application/json')
    except Exception as e:
        log('Error ' + str(e))
        raise

def custom_html_generator(offense_json):
    log ('Getting Mitre info')
    ruleidlist = ''
    for rule in offense_json["rules"]:
        if ruleidlist == '':
            ruleidlist = str(rule["id"])
        else:
            ruleidlist = ruleidlist + ',' + str(rule["id"])
    query_string = 'SELECT TACTICS::TACTICS(RULENAME(ENUMERATION('+ruleidlist+'))) AS \'Tacticas\' FROM events LIMIT 1'
    ariel = ArielSearch()
    timeout = 15
    sleep_interval = 20
    try:
        response = ariel.search_sync(query_string, timeout, sleep_interval)
        log('SearchID: ' + str(response[0]))
    except ArielError as error:
        log( str(error) )
    
    try:
        response = ariel.results(response[0])
        log('SearchResults: ' + str(response))
    except ArielError as error:
        log( str(error) )
    except ValueError as error:
        log( str(error) )

    return render_template('mitreinfo.html', rules=parsingRulesTactics(response))
    

def parsingRulesTactics(rules):
    log('Parsing Results')
    result = []
    rules = json.loads(rules["events"][0]["Tacticas"])
    for rule in rules:
        log(rule)
        newrule = {}
        newrule["name"] = rule
        newrule["tactics"] = []
        for tactic in rules[rule]:
            newtactic = {}
            newtactic["name"]=tactic
            newtactic["confidence"]=rules[rule][tactic]["confidence"]
            newtactic["id"]=rules[rule][tactic]["id"]
            newtactic["techniques"]=[]
            for technique in rules[rule][tactic]["techniques"]:
                newtechnique={}
                newtactic["techniques"].append(newtechnique)
            newrule["tactics"].append(newtactic)
        result.append(newrule)
    log (result)
    return result
