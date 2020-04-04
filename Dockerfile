FROM	debian:buster-slim

EXPOSE	10080

RUN		apt-get update && \
		apt-get install -y python3-pip openssh-client && \
		pip3 install gunicorn Flask Flask-HTTPAuth Jinja2 ldap3

ARG		PGID
ARG		PUID

RUN		PGID=${PGID:-1000} \
		PUID=${PUID:-1000} \
		groupadd -g "$PGID" webhooks && \
		useradd -d /webhooks -g webhooks -m -u "$PUID" webhooks

USER	webhooks:webhooks
ADD		. /webhooks
WORKDIR	/webhooks
VOLUME	/webhooks/.ssh

CMD		["gunicorn", "-b", "0.0.0.0:10080", "main:app"]
