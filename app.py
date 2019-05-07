#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : app.py.py
# @Author: harry
# @Date  : 2019/5/7 上午10:57
# @Desc  : flask app entry

import sqlite3
import bcrypt
from flask import Flask, g, request, jsonify, session
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = b'wehb2@8dfv)(*(><'
DATABASE = './app.db'


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def insert_db(query, args=(), one=False):
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    db.commit()
    return (rv[0] if rv else None) if one else rv


def insert_db_return_id(query, args=(), one=False):
    db = get_db()
    cur = db.cursor().execute(query, args)
    rv = cur.fetchall()
    gen_id = cur.lastrowid
    cur.close()
    db.commit()
    return (rv[0] if rv else None) if one else rv, gen_id


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/auth/register", methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        re_password = data['rePassword']
        if password != re_password:
            return jsonify(
                result=False,
                code=403,
                msg="两次输入的密码不一致",
                data=None,
            )
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            rst, uid = insert_db_return_id(
                '''INSERT INTO users (username, password) VALUES (?, ?)''',
                args=(username, hashed_password),
            )
        except sqlite3.IntegrityError:
            return jsonify(
                result=False,
                code=403,
                msg="用户名已存在",
                data=None,
            )

        return jsonify(
            result=True,
            code=200,
            msg="注册成功",
            data={
                'id': uid,
            }
        )


@app.route("/auth/login", methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        rst = query_db(
            '''SELECT * FROM users WHERE username=?''',
            args=[username],
        )
        if len(rst) == 0:
            return jsonify(
                result=False,
                code=403,
                msg="用户名或密码错误",
            )
        if not bcrypt.checkpw(password.encode('utf-8'), rst[0]['password']):
            return jsonify(
                result=False,
                code=403,
                msg="用户名或密码错误",
            )
        # successfully logged in, set session
        session['username'] = username
        session['uid'] = rst[0]['id']
        return jsonify(
            result=True,
            code=200,
            msg="登录成功",
        )


@app.route("/auth/logout", methods=['GET'])
def logout():
    if request.method == 'GET':
        session.pop('username')
        session.pop('uid')
        return jsonify(
            result=True,
            code=200,
            msg="注销成功",
        )
