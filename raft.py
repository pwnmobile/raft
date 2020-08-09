import sys
import os.path
import sqlite3
import argparse
import pcre
import textwrap
import time
from datetime import datetime
from colorama import Fore, Back, Style

parser = argparse.ArgumentParser(description='Parses log files in order to find new attacks & create snort rules.')
parser.add_argument('-a', action='store_true', help='Add new entries to database')
parser.add_argument('-c', action='store_true', help='Turn on content matching')
parser.add_argument('-p', action='store_true', help='Turn on PCRE matching')
parser.add_argument('-t', action='store_true', help='Record all malicious entries')
parser.add_argument('-v', action='store_true', help='Verbose output')
parser.add_argument('-vv', action='store_true', help='Very verbose output')
parser.add_argument('-s', nargs='?', help='Turn on overly promiscuous check', type=int)
parser.add_argument('-d', nargs='?', help='Path to database file', dest="database", type=str, default=False)
parser.add_argument('-r', nargs='?', required=True, help='Path to Snort rules to load', type=str)
parser.add_argument('--regex', nargs='?', help='Path to Regex', type=str)
parser.add_argument('path', help='specify log path')

### FUNCTIONS
# connect to database
def check_args(file_path):
    if file_path:
    	if os.path.isfile(file_path):
    		return open(file_path)
    	else:
    		print(("Error:", file_path, "doest not exist."))
    		sys.exit(1)

def make_tables_in_database(conn):
    global database
    conn.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='All Attacks'")
    print("[+] Loaded database: ", database)
    if conn.fetchone()[0]==1:
        conn.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='New Attacks'")
        print('[+] Tables exist.')
    else:
        conn.execute("CREATE TABLE 'All Attacks' (Date text, IP text, URI text, 'Snort Rule' text, Reference text, SID text, 'Attack Type' text)")
        conn.execute("CREATE TABLE 'New Attacks' (Date text, IP text, URI text, 'Snort Rule' text, SID text, 'Attack Type' text)")
        conn.execute("CREATE TABLE 'Anomalous Traffic' (Date text, IP text, URI text)")
        print('[+] Creating new tables.')

def check_database_for_previous_entries(conn, timestamp, source):
    conn.execute("SELECT Date, IP FROM 'All Attacks' WHERE Date=? AND IP =?", (timestamp, source,))
    result = conn.fetchone()
    if result: return True
    else: return False

def check_database_for_attack(uri, conn):
    conn.execute("SELECT URI FROM 'New Attacks' WHERE URI=?",(uri,))
    result = conn.fetchone()
    if result: return True
    else: return False

def add_database_entries(conn, timestamp, source, data, rule, ref, sid, classtype):
    data = " ".join(data) + " "
    rule = "".join(rule) + ""
    ref = " ".join(ref) + " "
    global args, anomaly_score
    if args.t:
        conn.execute("INSERT INTO 'All Attacks' VALUES (?, ?, ?, ?, ?, ?, ?)", (timestamp, source, data, rule, ref, sid, classtype))
    attack_result = check_database_for_attack(data, conn)
    if not attack_result:
        global new_entry_counter
        conn.execute("INSERT INTO 'New Attacks' VALUES (?, ?, ?, ?, ?, ?)", (timestamp, source, data, rule, sid, classtype))
        new_entry_counter = new_entry_counter + 1

def anomalous_traffic(conn, date, source, uri):
    conn.execute("SELECT Date, IP FROM 'Anomalous Traffic' WHERE Date=? AND IP =?", (date, source,))
    result = conn.fetchone()
    if not result:
        if args.v:
            print(Fore.RED + "[+] Anomalous traffic detected.  Entry is missing an HTTP method or HTTP protocol.", Style.RESET_ALL + "\nURI: " + value + "\n")
        conn.execute("INSERT INTO 'Anomalous Traffic' VALUES (?, ?, ?)", (date, source, str(uri)))

def parse_log_entries_into_dict(loglist):
    dict = {}
    dict['IP'] = loglist[0]
    dict['Date'] = loglist[1]
    reqList = loglist[2].split()
    dict['Request String'] = reqList
    dict['Response Type'] = loglist[3]
    dict['User Agent'] = loglist[6]
    return dict

def split_with_commas_outside_of_quotes(string, ruleparsing):
    arr = []
    start, flag, in_pcre = 0, False, False
    for pos, x in enumerate(string):
        if x == '"' and in_pcre == False:
            flag = not(flag)
        if ruleparsing and flag == False:
            if string[pos:pos+5] == 'pcre:': # Added this to account for PCRE where there may be an unknown number of " or ;
                in_pcre = True
        if ((flag == False and in_pcre == False) and x == ';') or (in_pcre == True and (x == ';' and string[pos-1:pos+2] == '"; ')):
            arr.append(string[start:pos])
            start = pos+1
            in_pcre = False
    # arr.append(string[start:pos])
    return arr

def result_format(q, r, s, t, u, v, w):
    format = {}
    format['msg'] = q
    format['Request String'] = r
    format['Date'] = s
    format['Reference'] = t
    format['IP Address'] = u
    format['Original Rule'] = v
    format['Attack Type'] = w
    return format

def wrapper(x,y):
    w = x + " " * (20 - len(x))
    return textwrap.TextWrapper(initial_indent=w, width=y, subsequent_indent=' '*20)

def too_many_matches(previous_rule, current_rule, counter, max_num):
    if previous_rule == current_rule:
        counter = counter + 1
    else:
        previous_rule = current_rule
        counter = 1
    if counter >= max_num:
        global joinrequestString, rule, disabled_rules
        print(Fore.RED + "\nINFO:",max_num," matches in a row were detected with the following rule:", Style.RESET_ALL)
        print(rule['msg'], "( Rule SID: ", rule['sid'], ") \n")
        print("With the following string:")
        print(joinrequestString)
        print("\nIf necessary, you can turn this rule off by adding a # in front of it in your ruleset.")
        print(Fore.YELLOW + "Current Disabled Rules: ", disabled_rules, Style.RESET_ALL)
        break_point = input("Do you want to temporarily turn off this rule? Y or N \n")
        if break_point == "Y":
            disabled_rules.append(rule['sid'])
        counter = 0
    return current_rule, counter

def result_found(message, request_String, date_time, reference, ipaddress, originalrule, sid, classtype):
    global args, to_many_matches_rule, to_many_matches_counter, database_entry_counter
    if args.v or args.vv:
        print(Fore.RED + "[+] Found a match. Rule SID: ", sid, Style.RESET_ALL)
        print(message,"\n")
        if args.vv:
            print("Date: ", date_time)
            print("IP Address: ", ipaddress)
            print("URI: " + " ".join(request_String), "\n")
    database_entry_counter = database_entry_counter + 1
    this_results.append(result_format(message,request_String,date_time,reference,ipaddress,originalrule,classtype))
    add_database_entries(database_connection, date_time, ipaddress, request_String, message, reference, sid, classtype)
    if args.s: to_many_matches_rule, to_many_matches_counter = too_many_matches(to_many_matches_rule, sid, to_many_matches_counter, args.s)

def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timeformat = '{:02d}'.format(secs)
        print(timeformat, end='\r')
        time.sleep(1)
        t -= 1

args = parser.parse_args()
if args.vv: args.v = True
print(Fore.GREEN + "")
print("                 .d888888            ")
print("                d88P' 888            ")
print("                888   888            ")
print("888d888 8888b.  888888888888         ")
print("888P'      '88b 888   888            ")
print("888    .d888888 888   888            ")
print("888    888  888 888   Y88b.          ")
print("888    'Y888888 888    'Y888         ")
print("" + Style.RESET_ALL)
print("Raft: Looking for malicious traffic in logs \n")
print("Break glass to prevent drowning \n")
print("Great way to filter out traffic by people who just do it for the lulz!")
print("                                                     - Satisfied User\n")
# check if database switch was used, if not, make a new databaseconn
if not args.database: database = "parse.db"
else: database = args.database

# build database connection
try:
    sqlite_connection = sqlite3.connect(database)
    database_connection = sqlite_connection.cursor()
except KeyboardInterrupt:
    sqlite_connection.commit()
    sqlite_connection.close()

# Declarations
## Counters
new_entry_counter, database_entry_counter, current_line_number, to_many_matches_counter  = 0, 0, 0, 0

# Lists
ruleset, this_results, disabled_rules = [], [], []
numberofTypesofAttacks = {}
to_many_matches_rule = None
# check to make sure paths are real, open files if so
f = check_args(args.path)
snortRulesFile = check_args(args.r)

# count to determine number of log lines and rules
num_of_Rules = sum(1 for l in open(args.r))
num_lines = sum(1 for l in open(args.path))

for snortRule in snortRulesFile:
    snort_Rules_Dict = {}
    if snortRule == "\n" or snortRule[0] == "#" or snortRule == "": continue # skip lines that are commented out
    original_rule = snortRule
    snortRule = snortRule[snortRule.find('('):][1:][:-2] # trim up to beginning of rule options
    snortRule = split_with_commas_outside_of_quotes(snortRule, True)
    for ruleOptions in snortRule:
        snort_option_key_and_value = ruleOptions.split(":")
        if len(snort_option_key_and_value) == 2: # if the option includes a key and a value, then add it
            snort_option_key = snort_option_key_and_value[0].lstrip(" ").lstrip('"').rstrip('"') #trim empty spaces or quotes
            snort_option_value = snort_option_key_and_value[1].lstrip(" ").lstrip('"').rstrip('"') #trim empty spaces or quotes
            if snort_option_key == "pcre":
                snort_option_value = snort_option_value.lstrip("/").rstrip(snort_option_value[snort_option_value.rindex('/')+1:]).rstrip('/')
            if snort_option_key in snort_Rules_Dict: # if key already exists, then convert the value into a list and store it in the dict
                newList = [] # list to put values in if there are multiples
                if isinstance(snort_Rules_Dict[snort_option_key], __builtins__.list): # check if is a list
                    snort_Rules_Dict[snort_option_key].append(snort_option_value) # if the value is already a list, then append the value to the list
                else: # if the value is not a list yet, then make a new list and add the values to it then add tot he dictionary
                    newList = [snort_option_value, snort_Rules_Dict[snort_option_key]]
                    snort_Rules_Dict[snort_option_key] = newList
            else: # if there aren't multple values, just add a new value and key
                snort_Rules_Dict[snort_option_key] = snort_option_value
        else: # if the option doesn't include a value, skip it
           continue
    snort_Rules_Dict['Original Rule'] = original_rule # retaining the original rule so they can be printed if necessary
    if 'reference' not in snort_Rules_Dict: snort_Rules_Dict['reference'] = "" # was getting errors about not having a reference key.
    ruleset.append(snort_Rules_Dict) # add each rule thats been dictionarized into the main list of rules
print(Fore.GREEN + "[+]",len(ruleset), "rules loaded out of", num_of_Rules, Style.RESET_ALL)
print("[+] If this doesn't seem right, you may need to uncomment some rules.")

# /Snort ruleset
if args.a:
    make_tables_in_database(database_connection) # make connection to database and make new table if necessary
    print(Fore.GREEN + "[+] Log file has", num_lines, "lines.\n", Style.RESET_ALL)
    countdown(3)

    for line in f: # for every line in the log file
        if current_line_number % 1000 == 0 and current_line_number != 0:
            print(Fore.BLUE + "Progress Report: Processing line ", current_line_number, Style.RESET_ALL)
        current_line_number += 1
        # Declarations
        http_method_in_uri, http_protocol, uri, has_pcre, fast_pattern_match = False, False, False, False, False
        malicious_score, anomaly_score = 0, 0

        if '\\x16\\x03' in line: continue # This is just somebody connecting HTTPS to an HTTP server
        # load custom regexes
        if args.regex:
            if check_args(args.regex):
                custom_regex = open(args.regex)
            regexes = custom_regex
        else:
            regexes = ['([(\d\.)]+) (?:.+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
                '([(\d\.)]+) ([(\d\.)]+) (?:.+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
                '((.*?:.?)?) (?:.+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"']
        for regs in regexes: # try all the regexes to see which one may match
            logline = pcre.match(regs, line) # if a regex string matches with the logline, break it into groups
            if logline:
                logline = pcre.match(regs, line).groups()
                break # exit out of loop after match is made
        if not logline:
            print("This did not match any regex: ", line) # if a regex match is not found, skip it
            continue
        currentloglineDict = parse_log_entries_into_dict(logline) # break the fields in logline out into dictionary entries
        if check_database_for_previous_entries(database_connection,currentloglineDict['Date'],currentloglineDict['IP']): continue # check database to see if this is already in there
        joinrequestString = []
        joinrequestString = " ".join(currentloglineDict['Request String'])
        http_methods = ["GET","POST","HEAD","PUT","DELETE","CONNECT","OPTIONS","TRACE"]
        if isinstance(currentloglineDict['Request String'], __builtins__.list):
            for value in currentloglineDict['Request String']:
                if value in http_methods: http_method_in_uri = value
                elif "HTTP/" in value: http_protocol = value
                else: uri = value
        else: uri = currentloglineDict['Request String']
        if (http_method_in_uri or http_protocol) == False:
            anomaly_score = 1
            anomalous_traffic(database_connection,currentloglineDict['Date'],currentloglineDict['IP'],currentloglineDict['Request String'])
        malicious_score, anomaly_score = 0, 0
        if not ((uri  == "/") or (uri == False)) and args.c: # if content matching is turned on
            for rule in ruleset:
                # 1. Fast_pattern will match immediately
                # 2. Don't match if content is less than 2 characters
                # 2. PCRE will not match unless has a content match as well
                # if pcre == True and content == True: print "match"
                # 3. if content has one item and doesn't have PCRE, then match it.  If item has two or more, match two.
                # pcre and content match or just pcre if no content
                if rule['sid'] in disabled_rules: continue
                if 'content' in rule or 'uricontent' in rule:
                    if 'uricontent' in rule.keys():
                        if 'uricontent' in rule.keys() and 'content' in rule.keys(): # in the off change that there is both a uricontent and content field
                            snortruleContentField = []
                            snortruleContentField.append(rule['uricontent'])
                            snortruleContentField.append(rule['content'])
                            break
                        snortruleContentField = rule['uricontent']
                    else:
                        snortruleContentField = rule['content']
                    malicious_score = 0
                    if isinstance(snortruleContentField, __builtins__.list): # if there are multiple content fields, they'll be in a list
                        for individualcontentField in set(snortruleContentField): # for every field in the list
                            fields = individualcontentField.replace('"','').split(',') # remove the ecess characters and then split into multiple values if they exist
                            for i in fields:
                                if i in uri and not (i == '') and len(i) > 1:
                                    malicious_score = malicious_score + 1
                    else: # if there aren't multple content fields
                        fields = snortruleContentField.replace('"','').split(',') # remove the ecess characters and then split into multiple values if they exist
                        for i in fields:
                            if i in uri and not (i == '') and len(i) > 1:
                                malicious_score = malicious_score + 1
                    if 'pcre' in rule: # if the pcre key exists, then execute the regex portion
                        snortReg = rule['pcre']
                        if isinstance(snortReg, list):
                            snortReg = "(" + ") |(".join(snortReg).lstrip("/").rstrip("/i") + ")" #change to & from |
                        snortReg = snortReg.lstrip("/").rstrip("/i")
                        try:
                            result = pcre.match(snortReg, joinrequestString)
                        except:
                            snortReg = snortReg + (')')
                            result = pcre.match(snortReg, joinrequestString)
                        if result: malicious_score = malicious_score + 1
                        else: malicious_score = malicious_score - 1
                    if malicious_score > 1:
                        try:
                            classtype = rule['classtype']
                        except:
                            classtype = 'Unknown'
                        result_found(rule['msg'],currentloglineDict['Request String'],currentloglineDict['Date'],rule['reference'],currentloglineDict['IP'],rule['Original Rule'],rule['sid'],classtype)
                        if classtype in numberofTypesofAttacks:
                            numberofTypesofAttacks[classtype] = numberofTypesofAttacks[classtype] + 1
                        else:
                            numberofTypesofAttacks[classtype] = 1
sqlite_connection.commit()
sqlite_connection.close()

print("============================================== \n")
print(Fore.GREEN + "[+] Results:", Style.RESET_ALL)
print(str(database_entry_counter) + " New entries added to database")
print((new_entry_counter),"of new attacks found \n")
break_point = input("Press enter to view new entries. \n")
for i in this_results:
    request_as_a_string = " ".join(i['Request String']) + " "
    references_as_a_string = " ".join(i['Reference']) + " "
    print_wrap = wrapper('Rule: ',70)
    print(print_wrap.fill(i['msg']))
    print_wrap = wrapper('Timestamp: ',70)
    print(print_wrap.fill(i['Date']))
    print_wrap = wrapper('IP Address: ',70)
    print(print_wrap.fill(i['IP Address']))
    print_wrap = wrapper('Request String: ',70)
    print(print_wrap.fill(request_as_a_string))
    print_wrap = wrapper('Reference: ',70)
    print(print_wrap.fill(references_as_a_string))
    print_wrap = wrapper('Attack Type: ',70)
    print(print_wrap.fill(i['Attack Type']))
    print("")
print("")
print("============================================== \n")
print (Fore.GREEN + "Types of attacks and frequency (read from Snort Rules):\n", Style.RESET_ALL)
for key, value in numberofTypesofAttacks.items():
    w = key + " " * (40 - len(key)) + str(value)
    print (w)

print("============================================== \n")
# Print Snort Rules
display_rules = input("[+] " + Fore.YELLOW + "Do you want to print Snort rules? (Y or N)")
print (Style.RESET_ALL)

if display_rules in {'Y','','y'}:
    list_of_rules_from_results = []
    with open("snortRules.txt", "w") as text_file:
        # print("Purchase Amount: {}".format(TotalAmount), file=text_file)
        for i in this_results:
            if i['Original Rule'] not in list_of_rules_from_results:
                print(i['Original Rule'], file=text_file)
                list_of_rules_from_results.append(i['Original Rule'])
    print("[+] Rules output to snortRules.txt.")
