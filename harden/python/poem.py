#!/usr/bin/env python2.7

from bottle import route, post, get, run, template, request, response, static_file, redirect
import bottle
import urllib2
import json
import random
import hashlib

secret = random.random()
api_get = 'http://localhost:8080/api/get'
api_get_all = 'http://localhost:8080/api/get/all'
api_save = 'http://localhost:8080/api/save'

@get('/')
def index():
    lang = request.query.lng
    if lang == '':
        lang = 'english'
    req = urllib2.Request(api_get, headers={'C_NAME': 'poem', 'E_LNG': lang.lower()})
    res = urllib2.urlopen(req, timeout=1).read()
    data = json.loads(res)
    u = request.get_cookie('u', secret=secret)
    private = request.get_cookie('p', secret=secret)
    return template('index', data=data, u=u, private=private)

@post('/login')
def login():
    l = request.forms.get('login')
    p = hashlib.sha512(request.forms.get('password')).hexdigest()
    req = urllib2.Request(api_get, headers={'C_NAME': 'user', 'E_LOGIN': l, 'E_PASS': p})
    res = urllib2.urlopen(req, timeout=1).read()
    data = json.loads(res)
    if data is not None:
        response.set_cookie('u', l, secret=secret)
        response.set_cookie('p', data['private'], secret=secret)
    redirect('/', 302)

@get('/logout')
def logout():
    response.delete_cookie('u')
    response.delete_cookie('p')
    redirect('/', 302)

@post('/post/comment')
def post_comment():
    u = request.get_cookie('u', secret=secret)
    if u:
        req = urllib2.Request(api_save, data="", headers={'C_NAME': 'comment', 'E_A': u, 'E_T': request.forms.get('comment'), 'E__TS': 'now'})
        cid = urllib2.urlopen(req, timeout=1).read()
    redirect('/', 302)

@get('/comments')
def comments():
    l = request.query.limit
    if l == '':
        l = 10
    req = urllib2.Request(api_get_all, headers={'C_NAME': 'comment', 'C_LIMIT': l})
    data = urllib2.urlopen(req, timeout=1).read()
    return data

@get('/registration')
def registration():
    return template('registration')

@post('/register')
def register():
    l = request.forms.get('login')
    p = hashlib.sha512(request.forms.get('password')).hexdigest()
    private = request.forms.get('private')

    req = urllib2.Request(api_save, data="", headers={'C_NAME': 'user', 'E_LOGIN': l, 'E_PASS': p, 'E_PRIVATE': private})
    uid = urllib2.urlopen(req, timeout=1).read()
    response.set_cookie('u', l, secret=secret)
    response.set_cookie('p', private, secret=secret)
    redirect('/', 302)

@route('/static/<filepath:path>')
def server_static(filepath):
    return static_file(filepath, root='./static/files/')

import amnesia
run(host='localhost', port=2013)
