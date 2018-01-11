#!/usr/bin/env python

# Copyright (C) 2014-2015 Nginx, Inc.

from __future__ import print_function, division, absolute_import

import argparse
import base64
import traceback
import BaseHTTPServer
import SocketServer

import ldap


BASIC_HEADER_PREFIX = 'basic '


class NoResultsException(Exception):
    pass


class EmptyPasswordException(Exception):
    pass


class HTTPAuthHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    _ctx = {}

    def do_GET(self):
        """
        Set ctx['user'] and ctx['pass'] for future LDAP authentication if credentials were sent,
        otherwise prompt client to send them via HTTP 401 Unauthorized.

        Returns True if request is processed and response sent, False otherwise.
        """
        self.log_message('parsing input parameters')
        for key, (header, value) in self.params.items():
            self._ctx[key] = self.headers.get(header, value)

        self.log_message('performing authorization')
        auth_header = self.headers.get('Authorization')
        if auth_header is None or not auth_header.lower().startswith(BASIC_HEADER_PREFIX):
            self._send_unauthorized()
            return True
        else:
            try:
                self.log_message('decoding credentials')
                auth_decoded = base64.b64decode(auth_header[len(BASIC_HEADER_PREFIX):])
                self._ctx['user'], self._ctx['pass'] = auth_decoded.split(':', 1)
                return False
            except Exception as ex:
                self._auth_failed(ex)
                return True

    def _send_unauthorized(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate',
                         'Basic realm="{}"'.format(self._ctx['realm']))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

    def _auth_failed(self, exception):
        self.log_message('url=%s, user=%s failed:\n%s',
                         self._ctx['url'] if 'url' in self._ctx else '-',
                         self._ctx['user'] if 'user' in self._ctx else '-',
                         traceback.format_exc(exception))
        self._send_unauthorized()


class LDAPAuthHandler(HTTPAuthHandler):
    DEFAULT_PARAMS = {
        'realm': ('X-Ldap-Realm', 'Restricted'),
        'url': ('X-Ldap-URL', None),
        'starttls': ('X-Ldap-Starttls', 'false'),
        'noreferrals': ('X-Ldap-NoReferrals', 'false'),
        'basedn': ('X-Ldap-BaseDN', None),
        'template': ('X-Ldap-Template', '(cn={username})'),
        'binddn': ('X-Ldap-BindDN', ''),
        'bindpasswd': ('X-Ldap-BindPass', ''),
    }

    def do_GET(self):
        try:
            self.log_message('initializing basic auth handler')
            if HTTPAuthHandler.do_GET(self):
                return

            self.log_message('checking for empty password')
            if not self._ctx['pass']:
                raise EmptyPasswordException()

            self.log_message('initializing LDAP connection')
            ldap_obj = ldap.initialize(self._ctx['url'])
            ldap_obj.protocol_version = ldap.VERSION3

            if self._ctx['starttls'] == 'true':
                ldap_obj.start_tls_s()
            if self._ctx['noreferrals'] == 'true':
                ldap_obj.set_option(ldap.OPT_REFERRALS, 0)

            self.log_message('binding as search user')
            ldap_obj.bind_s(self._ctx['binddn'], self._ctx['bindpasswd'], ldap.AUTH_SIMPLE)

            self.log_message('preparing search filter')
            search_filter = self._ctx['template'].format(username=self._ctx['user'])

            self.log_message('searching on server "%s" with base dn "%s" with filter "%s"',
                             self._ctx['url'],
                             self._ctx['basedn'],
                             search_filter)

            self.log_message('running search query')
            results = ldap_obj.search_s(self._ctx['basedn'],
                                        ldap.SCOPE_SUBTREE,
                                        search_filter,
                                        ['objectclass'],
                                        1)

            self.log_message('verifying search query results')
            if not results:
                raise NoResultsException()

            ldap_dn = results[0][0]
            self.log_message('binding as an existing user "%s"', ldap_dn)
            ldap_obj.bind_s(ldap_dn, self._ctx['pass'], ldap.AUTH_SIMPLE)

            self.log_message('auth OK for user "%s"', self._ctx['user'])
            self.send_response(200)
            self.end_headers()
        except Exception as ex:
            self._auth_failed(ex)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Simple Nginx LDAP authentication helper.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False,
    )
    listen_group = parser.add_argument_group('Listen options')
    listen_group.add_argument('-h', '--host', default='localhost', help='host to bind')
    listen_group.add_argument('-p', '--port', type=int, default=8888, help='port to bind')
    ldap_group = parser.add_argument_group(title='LDAP options')
    ldap_group.add_argument('-u', '--url', help='LDAP URI to query')
    ldap_group.add_argument('-s', '--starttls', help='Establish a STARTTLS protected session')
    ldap_group.add_argument('-r', '--noreferrals', help='Disable referrals (see https://www.python-ldap.org/en/latest/faq.html)')
    ldap_group.add_argument('-b', '--basedn', dest='basedn', help='LDAP base DN')
    ldap_group.add_argument('-D', '--binddn', dest='binddn', help='LDAP bind DN')
    ldap_group.add_argument('-w', '--bindpasswd', dest='bindpasswd', help='LDAP password for the bind DN')
    ldap_group.add_argument('-t', '--template', help='LDAP filter string template')
    http_group = parser.add_argument_group(title='HTTP options')
    http_group.add_argument('-R', '--realm', help='HTTP auth realm')
    parser.add_argument('--help', action='help', help='show this help message and exit.')
    parser.set_defaults(**{key: default for key, (header, default) in LDAPAuthHandler.DEFAULT_PARAMS.items()})

    args = parser.parse_args()
    LDAPAuthHandler.params = {key: (header, getattr(args, key)) for key, (header, default) in LDAPAuthHandler.DEFAULT_PARAMS.items()}

    print('Start listening on {}:{}...'.format(args.host, args.port))
    server = SocketServer.ThreadingTCPServer((args.host, args.port), LDAPAuthHandler)
    server.serve_forever()
