# raft
Raft provides administrators a quick and easy way to iterate through web server or honeypot logs and determine if any new (or undocumented) attacks have occurred and match them to specific CVEs if they are available.  This is also to combat alert fatigue through log flooding, which is the significance of the name Raft: to provide assistance when drowning in a (log) flood.  Most Snort rules that are generated by Talos include references for the specific CVE or Bugtraq number so that administrators can research the specific attack that Snort has alerted.  This tool will use the content matching fields available in Snort rules, and also catalog specific malicious traffic into a database file and then use that to compare new traffic against to find new attacks.

# Requirements:
Make sure you're running the most current version of Python 3.

You can run pip3 install requirements.txt

To install the Python PCRE module, run the following command:

sudo pip3 install python-pcre

If having issues with installing PCRE, try runing this first:

sudo apt-get install libpcre3-dev
sudo yum install pcre-devel

# Usage:
logfile.py [-h] [-a] [-c] [-p] [-t] [-v] [-vv] [-s [S]] [-d [DATABASE]] -r [R] [--regex [REGEX]] path

Parses log files in order to find new attacks & create snort rules.

positional arguments:
  path             specify log path
optional arguments:
  -h, --help       show this help message and exit
  -a               Add new entries to database
  -c               Turn on content matching
  -p               Turn on PCRE matching
  -t               Record all malicious entries
  -v               Verbose output
  -vv              Very verbose output
  -s [S]           Turn on overly promiscuous check
  -d [DATABASE]    Path to database file
  -r [R]           Path to Snort rules to load
  --regex [REGEX]  Path to Regex

# Notes:
If the –regex is used, the default regex strings will not be loaded.

Once Raft is finished running, it will display the values that it found as well as a wrap up of the type of attacks detected and the frequency:

============================================== 
Types of attacks and frequency:

attempted-admin                         62
web-application-attack                  196
policy-violation                        27
attempted-user                          29
attempted-recon                         25
bad-unknown                             20

============================================== 

This information is taken from the Snort Rules 'classtype' field within the rule.  If the rule does not have this value, then the result will be recorded as 'Unknown.'
