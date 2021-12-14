# Licensed Materials - Property of IBM
# 5725I71-CC011829
# (C) Copyright IBM Corp. 2015, 2020. All Rights Reserved.
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.

from flask import Blueprint, render_template, current_app, send_from_directory , Response
from qpylib import qpylib
import json
from qpylib.offense_qpylib import get_offense_json_html
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

# The restmethod invoked to get the HTML code to include in the Offense panel
@viewsbp.route('/mitreinfo/<offense_id>', methods=['GET'])
def get_offense(offense_id):
    try:
        offense_json = get_offense_json_html(offense_id, custom_html_generator)
        return Response(response=offense_json, status=200, mimetype='application/json')
    except Exception as e:
        qpylib.log('Error ' + str(e) , level='ERROR')
        raise

def custom_html_generator(offense_json):
    '''
        This function get the mitre information related to an offense 
        and return the html code to show in the offense.
    '''
    qpylib.log ('Getting Mitre info', level='INFO')
    # Create the list of rule ids involved in the offense
    ruleidlist = ''
    for rule in offense_json["rules"]:
        if ruleidlist == '':
            ruleidlist = str(rule["id"])
        else:
            ruleidlist = ruleidlist + ',' + str(rule["id"])
    # Build the AQL to get the Mitre info
    query_string = 'SELECT TACTICS::TACTICS(RULENAME(ENUMERATION('+ruleidlist+'))) AS \'Tacticas\' FROM events LIMIT 1'
    ariel = ArielSearch()
    # Run am Ariel synch search 
    timeout = 15
    sleep_interval = 2
    try:
        response = ariel.search_sync(query_string, timeout, sleep_interval)
        qpylib.log('SearchID: ' + str(response[0]), level='DEBUG')
    except ArielError as error:
        qpylib.log( str(error), level='ERROR' )
    # Get search Results    
    try:
        response = ariel.results(response[0])
        qpylib.log('SearchResults: ' + str(response), level='DEBUG')
    except ArielError as error:
        qpylib.log( str(error), level='ERROR' )
    except ValueError as error:
        qpylib.log( str(error), level='ERROR' )

    # Render the result into HTML format
    return render_template('mitreinfo.html', rules=parsingRulesTactics(response))
    

def parsingRulesTactics(rules):
    '''
        This function formats the mitre information into an array easier to process by Jinja template
    '''
    qpylib.log('Parsing Results', level='INFO')
    result = []
    rules = json.loads(rules["events"][0]["Tacticas"])
    for rule in rules:
        qpylib.log(rule, level='DEBUG')
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
    qpylib.log (result , level='DEBUG')
    return result
