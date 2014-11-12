#!/usr/bin/python
# Copyright (C) 2014 Red Hat, Inc.
# Copyright (C) 2005, 2006, 2007 Florian Weimer
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import cookielib
import json
import os
import sqlite3
import sys
import urllib2

from glob import glob

if len(sys.argv) != 3:
    sys.stderr.write("""usage:
    {0[0]} get ZIMBRA-URL
    {0[0]} set ZIMBRA-URL
""".format(sys.argv))
    sys.exit(1)

command = sys.argv[1]
zimbra_url = sys.argv[2]
while zimbra_url[-1:] == "/":
    zimbra_url = zimbra_url[:-1]

# Copied from debsecan 0.4.17.  ca_certs path has been adjusted.
def patch_https_implementation():
    "Add certificate and host name checking to the standard library."

    import ssl
    from inspect import stack
    from httplib import HTTPConnection

    wrap_socket_orig = ssl.wrap_socket
    def wrap_socket(sock, *args, **kwargs):
        kwargs["ca_certs"] = "/etc/pki/tls/certs/ca-bundle.crt"
        kwargs["cert_reqs"] = ssl.CERT_REQUIRED
        kwargs["ciphers"] = "HIGH:!aNULL:!SRP:!PSK"
        kwargs["do_handshake_on_connect"] = True
        kwargs["suppress_ragged_eofs"] = False
        secsock = wrap_socket_orig(sock, *args, **kwargs)

        # Implement host name check for httplib
        cert = secsock.getpeercert()
        caller = stack()[1]
        caller_locals = caller[0].f_locals
        try:
            caller_self = caller_locals["self"]
        except KeyError:
            caller_self = None
        if caller_self is not None and isinstance(caller_self, HTTPConnection):
            expected_host = caller_self.host
            try:
                subject_dn = cert["subject"]
            except KeyError:
                raise IOError("invalid X.509 certificate for " + expected_host)
            found = False
            expected = (("commonName", expected_host),)
            for entry in subject_dn:
                if entry == expected:
                    found = True
            if not found:
                raise IOError("X.509 certificate does not match host name " +
                              expected_host)
        else:
            raise IOError("ssl.wrap_socket called from unexpected place")

        return secsock
    ssl.wrap_socket = wrap_socket

patch_https_implementation()

def add_sqlite_cookies(jar, path):
    db = sqlite3.connect(path)
    for host, path, name, value, issecure, expiry in db.execute(
            "SELECT host, path, name, value, issecure, expiry FROM moz_cookies"):
        jar.set_cookie(cookielib.Cookie(
            version = 0,
            name = name,
            value = value,
            port = None,
            port_specified = False,
            domain = host,
            domain_specified = True,
            domain_initial_dot = host.startswith("."),
            path = path,
            path_specified = path is not None,
            secure = bool(issecure),
            expires = expiry,
            discard = False,
            comment = None,
            comment_url = None,
            rest = {}))

def add_session_cookies(jar, store):
    data = json.load(file(store))
    for window in data["windows"]:
        for cookie in window["cookies"]:
            def get(name):
                try:
                    value = cookie[name]
                except KeyError:
                    return None
                return value.encode("UTF-8")
            name = get("name")
            value = get("value")
            host = get("host")
            path = get("path")
            issecure = get("isSecure") is not None
            cookie = cookielib.Cookie(
                version = 0,
                name = name,
                value = value,
                port = None,
                port_specified = False,
                domain = host,
                domain_specified = True,
                domain_initial_dot = host.startswith("."),
                path = path,
                path_specified = path is not None,
                secure = bool(issecure),
                expires = None,
                discard = False,
                comment = None,
                comment_url = None,
                rest = {})
            jar.set_cookie(cookie)


def open_jar():
    """Selects the most recently modified Firefox profile and reads its cookies.

    Returns an urrlib2 URL opener which uses these cookies.
    """
    sqlite_name = "cookies.sqlite"
    session_name = "sessionstore-backups/recovery.js"
    candidates = os.environ["HOME"] + "/.mozilla/firefox/*/" + sqlite_name
    path = max([(os.stat(path).st_mtime, path) for path
               in glob(candidates)])[1]
    path = path[:-len(sqlite_name)]
    sys.stderr.write("info: selecting profile file: {!r}\n".format(path))

    jar = cookielib.CookieJar()
    add_sqlite_cookies(jar, path + sqlite_name)
    add_session_cookies(jar, path + session_name)

    return urllib2.build_opener(urllib2.HTTPCookieProcessor(jar))

def zimbra_post(opener, base, method, data):
    url = "{}/service/soap/{}".format(base, method)
    try:
        return opener.open(url, data = data)
    except urllib2.HTTPError as e:
        sys.stderr.write("*** Error response from server:\n");
        for key, value in sorted(vars(e).items()):
            sys.stderr.write("  {}: {}\n".format(repr(key), repr(value)))
        sys.stderr.write("*** Server data:\n  {!r}\n\n", e.fp.read())
        raise

opener = open_jar()

if command == "get":
    response = zimbra_post(opener, zimbra_url, "GetFilterRulesRequest",
"""<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <context xmlns="urn:zimbra">
      <format xmlns="" type="js"/>
   </context>
  </soap:Header>
  <soap:Body>
    <GetFilterRulesRequest xmlns="urn:zimbraMail"/>
  </soap:Body>
</soap:Envelope>
""")

    body = json.load(response)
    rules = body["Body"]["GetFilterRulesResponse"]["filterRules"]
    print json.dumps(rules, sort_keys=True, indent=4)
elif command == "set":
    rules = json.load(sys.stdin)
    request = {"Header" : {"ctxt": {}},
               "Body" : {"ModifyFilterRulesRequest" : {
                   "_jsns" : "urn:zimbraMail",
                   "filterRules" : rules}}}
    try:
        response = zimbra_post(opener, zimbra_url, "ModifyFilterRulesRequest",
                               json.dumps(request))
    except urllib2.HTTPError as e:
        print vars(e)
        print e.fp.read()
        raise
    print json.dumps(json.load(response), sort_keys=True, indent=4)
else:
    sys.stderr.write("error: invalid command: {!r}\n".format(command))
    sys.exit(1)
