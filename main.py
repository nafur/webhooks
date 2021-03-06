import base64
import hashlib
import hmac
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

def encode_script(script):
	return base64.b64encode(script.encode("utf8"), altchars = b"+-").decode("utf8")

def decode_script(script):
	return base64.b64decode(script.encode("utf8"), altchars = b"+-").decode("utf8")

@auth.verify_password
def ldap_login(username, password):
	try:
		ldapuser = 'uid={},{}'.format(username, config.LDAP_BASE_USERS)
		server = ldap3.Server(config.LDAP_SERVER, use_ssl = config.LDAP_USE_SSL)
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
# - Make sure the ssh key is in a format compatible with openssl rsautl (i.e. generated with -m PEM)
#   You can also convert it as follows: ssh-keygen -f id_rsa.pub -e -m PEM > id_rsa.pub.pem
# - Verify signature using the ssh public key
#   echo "<token>" | base64 -d | openssl rsautl -verify -inkey ~/.ssh/id_rsa.pub.pem -pubin
def verify_token(host, script, token):
	r = subprocess.run('base64 -d | openssl rsautl -verify -inkey .ssh/id_rsa.pub -pubin', input = token, text = True, capture_output = True, shell = True, cwd = os.path.expanduser('~'))
	if r.returncode != 0:
		app.logger.error("Token verification failed")
		return False
	if r.stdout.strip() != "{}:{}".format(host, script):
		app.logger.error("Incorrect token: {}:{} != {}".format(host, script, r.stdout.strip()))
		return False
	return True

def run_script(host, script):
	res = subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', '{}@{}'.format(config.SCRIPT_USER, host), "{} </dev/null &>/dev/null &".format(script)])
	app.logger.info("Executed {}@{}:{} and got the following:\n{}".format(config.SCRIPT_USER, host, script, res.stdout))
	return "Success!"

@app.route('/github/<host>/<script>', methods = ['POST'])
def github_run(host, script):
	if 'X-Hub-Signature' not in request.headers:
		return "You did not pass a token"
	payload = request.get_data(as_text = False)
	data = request.get_json()
	script = decode_script(script)
	token = generate_token("{}@{}".format(data['repository']['full_name'], host), script)
	signature = hmac.new(token.encode('utf8'), payload, hashlib.sha1).hexdigest()
	if hmac.compare_digest(signature, request.headers['X-Hub-Signature'].split('=')[1]):
		return run_script(host, script)
	return "Token verification failed!"

@app.route('/github/secret', methods = ['GET', 'POST'])
@auth.login_required
def github_token():
	if request.method == 'GET':
		return render_template('github-token-form.html')
	host = request.form.get('host')
	repo = request.form.get('repository')
	script = request.form.get('script')
	token = generate_token("{}@{}".format(repo, host), script)
	if not token:
		return "Token generation failed"
	return render_template('github-token-success.html', token = token, host = host, script = encode_script(script))

@app.route('/gitlab/<host>/<script>', methods = ['GET', 'POST'])
def gitlab_run(host, script):
	if 'X-Gitlab-Token' not in request.headers:
		return "You did not pass a token"
	script = decode_script(script)
	if not verify_token(host, script, token):
		return "Token verification failed"
	return run_script(host, script)

@app.route('/gitlab/token', methods = ['GET', 'POST'])
@auth.login_required
def gitlab_token():
	if request.method == 'GET':
		return render_template('gitlab-token-form.html')
	host = request.form.get('host')
	script = request.form.get('script')
	token = generate_token(host, script)
	if not token:
		return "Token generation failed"
	return render_template('gitlab-token-success.html', token = token, host = host, script = encode_script(script))

@app.route('/')
def index():
	data = {
		'index': { 'hide': True },
		'static': { 'hide': True },
		'github_token': {
			'title': 'GitHub secret generation',
			'description': 'Allows authorized users to generate new secrets that allow the execution of scripts via GitHub webhooks.',
			'link': True,
		},
		'github_run': {
			'title': 'GitHub endpoint',
			'description': 'GitHub endpoint for webhooks that need to call custom scripts.',
			'URL': {
				'host': 'Hostname to execute the script on.',
				'script': 'Filename of the script to be executed.',
			},
			'CUSTOM': {
				'Secret': 'Secret as obtained by <code>/github/secret</code> for this script.',
			}
		},
		'gitlab_token': {
			'title': 'Gitlab token generation',
			'description': 'Allows authorized users to generate new tokens that allow the execution of scripts via Gitlab webhooks.',
			'link': True,
		},
		'gitlab_run': {
			'title': 'Gitlab endpoint',
			'description': 'Gitlab endpoint for webhooks that need to call custom scripts.',
			'URL': {
				'host': 'Hostname to execute the script on.',
				'script': 'Filename of the script to be executed.',
			},
			'POST': {
				'X-Gitlab-Token': 'Authorization token as obtained by <code>/gitlab/token</code> for this script.',
			}
		},
	}
	return render_template('index.html', data = data, routes = app.url_map.iter_rules())
