FROM python:2-alpine

COPY nginx_ldap_auth_daemon.py /usr/src/app/

WORKDIR /usr/src/app/

# Install required software
RUN \
    apk --no-cache add openldap-dev && \
    apk --no-cache add --virtual build-dependencies build-base && \
    pip install python-ldap && \
    apk del build-dependencies

EXPOSE 8888

CMD ["python", "/usr/src/app/nginx_ldap_auth_daemon.py", "--host", "0.0.0.0", "--port", "8888"]
