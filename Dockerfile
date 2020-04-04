FROM	debian:buster-slim

EXPOSE	80

RUN		apt-get update && \
		apt-get install -y python3-pip && \
		pip3 install gunicorn Flask Flask-HTTPAuth Jinja2 ldap3

ADD		. /app
WORKDIR	/app


CMD		["gunicorn", "-b", "0.0.0.0:80", "main:app"]
