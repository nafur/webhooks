import ldap3
import logging
import os
import os.path
import subprocess
from syslog import *

from flask import Flask, render_template, request
app = Flask(__name__)

logger = logging.getLogger('gunicorn.error')
app.logger.handlers.extend(logger.handlers)
app.logger.setLevel(logging.DEBUG)

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

import config

@auth.verify_password
def ldap_login(username, password):
	try:
		ldapuser = 'uid={},{}'.format(username, config.LDAP_BASE_USERS)
		server = ldap3.Server(config.LDAP_SERVER, use_ssl = True)
		conn = ldap3.Connection(server, user = ldapuser, password = password, auto_bind = True)
		conn.search(config.LDAP_GROUP_DN, search_filter = config.LDAP_GROUP_FILTER, search_scope = ldap3.SUBTREE, attributes = [config.LDAP_MEMBER_ATTRIBUTE])
		return username in conn.entries[0].__getattr__(config.LDAP_MEMBER_ATTRIBUTE)
	except Exception as e:
		app.logger.error("LDAP authentication failed: {}".format(e))
		return False

# To generate a token
# - Sign script path using the ssh private key
#   echo "<script>" | openssl rsautl -sign -inkey ~/.ssh/id_rsa | base64
def generate_token(host, script):
	r = subprocess.run('openssl rsautl -sign -inkey .ssh/id_rsa | base64 -w0', input = "{}:{}".format(host, script), text = True, capture_output = True, shell = True, cwd = os.path.expanduser('~'))
	if r.returncode != 0:
		app.logger.error("Token generation failed")
		return False
	return r.stdout.strip()

# To verify:
# - Convert the ssh public key to a format compatible with openssl rsautl
#   cd /var/lib/tomcat9/.ssh ; ssh-keygen -f id_rsa.pub -e -m PKCS8 > id_rsa.pub.pem
# - Verify signature using the ssh public key
#   echo "<token>" | base64 -d | openssl rsautl -verify -inkey ~/.ssh/id_rsa.pub.pem -pubin
def verify_token(host, script, token):
	r = subprocess.run('base64 -d | openssl rsautl -verify -inkey .ssh/id_rsa.pub.pem -pubin', input = token, text = True, capture_output = True, shell = True, cwd = os.path.expanduser('~'))
	if r.returncode != 0:
		app.logger.error("Token verification failed")
		return False
	if r.stdout.strip() != "{}:{}".format(host, script):
		app.logger.error("Incorrect token: {}:{} != {}".format(host, script, r.stdout.strip()))
		return False
	return True

def script_run(host, script, token):
	if not verify_token(host, script, token):
		return "Token verification failed"
	subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', '{}@{}'.format(config.SCRIPT_USER, host), script])
	return "Success!"
	
@app.route('/gitlab/<host>/<script>', methods = ['GET', 'POST'])
def script_gitlab(host, script):
	if 'X-Gitlab-Token' not in request.headers:
		return "You did not pass a token"
	return run_script(host, script, str(request.headers['X-Gitlab-Token']))
	
@app.route('/token', methods = ['GET', 'POST'])
@auth.login_required
def token_generator():
	if request.method == 'GET':
		return render_template('script-token-form.html')
	host = request.form.get('host')
	script = request.form.get('script')
	token = generate_token(host, script)
	if not token:
		return "Token generation failed"
	return render_template('script-token-success.html', token = token, host = host, script = script)

@app.route('/')
def index():
	data = {
		'index': { 'hide': True },
		'static': { 'hide': True },
		'token_generator': {
			'title': 'Token generation',
			'description': 'Allows authorized users to generate new tokens that allow the execution of scripts.',
			'link': True,
		},
		'script_gitlab': {
			'title': 'Gitlab endpoint',
			'description': 'Gitlab endpoint for webhooks that need to call custom scripts.',
			'URL': {
				'host': 'Hostname to execute the script on.',
				'script': 'Filename of the script to be executed.',
			},
			'POST': {
				'X-Gitlab-Token': 'Authorization token as obtained by <code>/token</code> for this script.',
			}
		}
	}
	return render_template('index.html', data = data, routes = app.url_map.iter_rules())
