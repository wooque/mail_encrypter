import json
from datetime import datetime, timedelta
from hashlib import sha256
from collections import defaultdict

import jwt
from bottle import Bottle, request, HTTPError
from psycopg2 import IntegrityError, Binary
from psycopg2.pool import ThreadedConnectionPool

cfg = json.loads(open("config.json").read())
db = ThreadedConnectionPool(2, 4, host=cfg['db_host'], database="mail_encrypter",
                            user="mail_encrypter", password=cfg['db_pass'])
app = Bottle()


@app.post('create')
def create():
    for k in ['email', 'password']:
        if len(request.json.get(k, '')) > 128:
            return dict(error=k + " too long")

    for k in ['public_key', 'private_key']:
        if len(request.json.get(k, '')) > 4096:
            return dict(error=k + " too long")
    try:
        conn = db.getconn()
        c = conn.cursor()
        pass_hash = sha256(request.json['password']).hexdigest()
        c.execute("INSERT INTO keys(pass_hash, public, private) VALUES (%s, %s, %s) RETURNING id",
                  (pass_hash, Binary(request.json['public_key'].decode('hex')),
                   Binary(request.json['private_key'].decode('hex'))))

        key_id = c.fetchone()[0]
        c.execute("INSERT INTO emails(email, key) VALUES (%s, %s)", (request.json['email'], key_id,))
        return dict(id=key_id)
    
    except IntegrityError:
        raise HTTPError(409)
        
    finally:
        c.close()
        db.putconn(conn)


@app.post('/auth')
def auth():
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    if not email or not password:
        return {'error': 'Username or password missing'}

    pass_hash = sha256(password).hexdigest()
    conn = db.getconn()
    c = conn.cursor()
    c.execute("SELECT keys.id, encode(public,'hex'), encode(private,'hex') FROM keys, emails "
              "WHERE keys.id=emails.key AND lower(email)=lower(%s) AND pass_hash=%s",
              (email, pass_hash,))
    result = c.fetchone()
    c.close()
    db.putconn(conn)
    
    if not result:
        return {'error': 'Wrong username or password'}

    resp = {'key_id': result[0], 'public_key': result[1], 'private_key': result[2]}
    payload = {
        'sub': resp['key_id'],
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=14),
    }
    token = jwt.encode(payload, cfg['db_pass'])
    resp['token'] = token.decode('unicode_escape')
    return resp


def get_current_user(req):
    authorization = req.headers.get('Authorization')

    if not authorization:
        return None

    try:
        token = authorization.split()[1]
        payload = jwt.decode(token, cfg['db_pass'])

    except jwt.DecodeError:
        raise HTTPError(401, reason='Token is invalid')

    except jwt.ExpiredSignature:
        raise HTTPError(401, reason='Token has expired')

    user_id = payload.get('sub')

    if not user_id:
        raise HTTPError(401, reason='User not authorized')
    return user_id

PREPARED = defaultdict(list)


@app.get('/keys')
def get_keys():
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPError(403)
        
    users = request.query.dict.get('users')
    if users and not isinstance(users, list):
        users = [users]

    conn = db.getconn()
    c = conn.cursor()
    if users:
        if 'users_keys' not in PREPARED[conn]:
            c.execute("PREPARE users_keys AS SELECT email, encode(public, 'hex') FROM emails, keys "
                      "WHERE emails.key=keys.id AND email = ANY($1)")
            PREPARED[conn].append('users_keys')
        c.execute("EXECUTE users_keys (%s)", (users,))
        result = c.fetchall()
        c.close()
        db.putconn(conn)
        
        if len(result) != len(users):
            raise HTTPError(404)

        return dict(result)
    else:
        if 'my_keys' not in PREPARED[conn]:
            c.execute("PREPARE my_keys AS SELECT encode(public, 'hex'), encode(private, 'hex') FROM keys WHERE id=$1")
            PREPARED[conn].append('my_keys')
        c.execute("EXECUTE my_keys (%s)", (current_user,))
        result = c.fetchone()
        c.close()
        db.putconn(conn)
    
        if not result:
            raise HTTPError(404)

        return dict(public_key=result[0], private_key=result[1])


@app.post('/keys')
def update_keys():
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPError(403)
        
    data = json.loads(request.body)
    public = Binary(data['public_key'].decode('hex'))
    private = Binary(data['private_key'].decode('hex'))
    conn = db.getconn()
    c = conn.cursor()
    c.execute("UPDATE keys SET public = %s, private = %s WHERE id=%s", (public, private, current_user,))
    c.close()
    db.putconn(conn)
    return

if __name__ == '__main__':
    app.run(port=8080)
