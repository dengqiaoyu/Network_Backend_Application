#!/usr/bin/env python
#
# This script shows how to use Flask within a WSGI wrapper for CGI.
# Flask is a WSGI framework, so we need to translate CGI into WSGI.
#
# Authors: Athula Balachandran <abalacha@cs.cmu.edu>,
#          Charles Rang <rang@cs.cmu.edu>,
#          Wolfgang Richter <wolf@cs.cmu.edu>

import os, sys

# From Flask: http://flask.pocoo.org/docs/quickstart/
############### BEGIN FLASK QUICKSTART ##############
from sqlite3 import dbapi2 as sqlite3

ALLDIRS = [os.path.expanduser("~") + '/flask_env/lib/python2.6/site-packages']

import sys 
import site 
import getpass

TMP_DIR = '/tmp/' + getpass.getuser()
if not os.path.exists(TMP_DIR):
    os.makedirs(TMP_DIR)

# Remember original sys.path.
prev_sys_path = list(sys.path) 

# Add each new site-packages directory.
for directory in ALLDIRS:
    site.addsitedir(directory)

# Reorder sys.path so new directories at the front.
new_sys_path = [] 
for item in list(sys.path): 
    if item not in prev_sys_path: 
        new_sys_path.append(item) 
        sys.path.remove(item) 
        sys.path[:0] = new_sys_path 

from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash


# create our little application :)
app = Flask(__name__)

# Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE=TMP_DIR + '/flaskr.db',
    DEBUG=True,
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)


def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def init_db():
    """Creates the database tables."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/')
def show_entries():
    with open(TMP_DIR + '/vars.out', 'w') as f:
        f.write('%s' % os.environ)
    f.closed
    db = get_db()
    cur = db.execute('select title, text from entries order by id desc')
    entries = cur.fetchall()
    return render_template('show_entries.html', entries=entries)


@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    db.execute('insert into entries (title, text) values (?, ?)',
                 [request.form['title'], request.form['text']])
    db.commit()
    flash('New entry was successfully posted')
    return redirect(url_for('show_entries'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid username'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('show_entries'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('show_entries'))

################ END FLASK QUICKSTART ###############

# From PEP 333: http://www.python.org/dev/peps/pep-0333/
############### BEGIN WSGI WRAPPER ##############
def run_with_cgi(application):

    environ = dict(os.environ.items())
    environ['wsgi.input']        = sys.stdin
    environ['wsgi.errors']       = sys.stderr
    environ['wsgi.version']      = (1, 0)
    environ['wsgi.multithread']  = False
    environ['wsgi.multiprocess'] = True
    environ['wsgi.run_once']     = True

    if environ.get('HTTPS', 'off') in ('on', '1'):
        environ['wsgi.url_scheme'] = 'https'
    else:
        environ['wsgi.url_scheme'] = 'http'

    headers_set = []
    headers_sent = []

    def write(data):
        with open(TMP_DIR + '/response.out', 'a') as f:
            if not headers_set:
                 raise AssertionError("write() before start_response()")

            elif not headers_sent:
                 # Before the first output, send the stored headers
                 status, response_headers = headers_sent[:] = headers_set
                 http_version = environ.get('SERVER_PROTOCOL', 'HTTP/1.1')
                 http_connection = environ.get('HTTP_CONNECTION','close')
                 sys.stdout.write('%s %s\r\n' % (http_version, status))
                 #f.write('%s %s\r\n' % (http_version, status))
                 sys.stdout.write('Connection: %s\r\n' % (http_connection))
                 f.write('Connection: %s\r\n' % (http_connection))
                 for header in response_headers:
                     sys.stdout.write('%s: %s\r\n' % header)
                     f.write('%s: %s\r\n' % header)
                 sys.stdout.write('\r\n')
                 f.write('\r\n')

            sys.stdout.write(data)
            f.write(data)
            sys.stdout.flush()
            f.flush()
        f.closed

    def start_response(status, response_headers, exc_info=None):
        if exc_info:
            try:
                if headers_sent:
                    # Re-raise original exception if headers sent
                    raise exc_info[0], exc_info[1], exc_info[2]
            finally:
                exc_info = None     # avoid dangling circular ref
        elif headers_set:
            raise AssertionError("Headers already set!")

        headers_set[:] = [status, response_headers]
        return write

    result = application(environ, start_response)
    try:
        for data in result:
            if data:    # don't send headers until body appears
                write(data)
        if not headers_sent:
            write('')   # send headers now if body was empty
    finally:
        if hasattr(result, 'close'):
            result.close()
############### END WSGI WRAPPER ##############

if __name__ == '__main__':
    init_db()
    run_with_cgi(app)
