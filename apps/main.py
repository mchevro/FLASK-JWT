#Source From : https://www.youtube.com/watch?v=e-_tsR0hVLQ
from flask import Flask, jsonify, request, session, render_template, flash, make_response
from functools import wraps
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = b'_\x00\xc0\x90\x08\x88C\xfb\xf8\x13\xe8\\\xb3\x1f4\x14'

def check_for_token(func): #Fungsi untuk cek parameter token
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token: #Jika tidak ada parameter token maka responya seperti ini
            return jsonify({'message': 'Missing Token'}), 403
        try: #mencoba melakukan decode token 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
        except: #Jika token salah maka responya seperti ini
            return jsonify({'message': 'Invalid Token'}), 403
        return func(*args, **kwargs)
    return wrapped

@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'Currently Logged In'

@app.route('/login', methods=['POST']) #Proses Login
def login():
    if request.form['username'] and request.form['password'] == 'password':
        session['logged_in'] = True
        token = jwt.encode({ #Membuat Token
            'user': request.form['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60) #Masa berlaku token 60 Detik
        },
        app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    else:
        return make_response('Unable to verivy', 403, {'WWW-Authenticate': 'Basic realm: "Login"'})

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return 'Hapus Session'

@app.route('/public')
def public():
    return 'For Public' #Bisa dilihat tanpa token

@app.route('/auth')
@check_for_token
def authorized():
    return 'This is only viewble with a token' #Wajib mengggunakan parameter token untuk melihatnya

if __name__ == '__main__':
    app.run(debug=True)