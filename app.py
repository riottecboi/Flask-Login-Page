import flask
from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_wtf.csrf import CSRFProtect
from flask_env import MetaFlaskEnv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datamodel import Base, User
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from Google import Create_Service
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
import os
import json

app = Flask(__name__)

class Configuration(metaclass=MetaFlaskEnv):
    SECRET_KEY = "supersecretkey"
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://localhost:3306/testlogin?user=root&password=root'
    POOL_SIZE = 5
    POOL_RECYCLE = 60
    SENDER = "tranvinhliem1307@gmail.com"
    SENDER_PASSWORD = "a58evwck"
    GOOGLE_CLIENT_ID = '87230437389-bqr548s8kk74bd8atldtopc8vsiq1i61.apps.googleusercontent.com'
    GOOGLE_REDIRECT_URI = 'http://127.0.0.1:5000/gCallback'
    EMAIL_HOST = '127.0.0.1'
    EMAIL_PORT = 5500

try:
    app.config.from_pyfile('settings.cfg')
except FileNotFoundError:
    app.config.from_object(Configuration)
config = {}
with open('credentials.json', encoding='utf-8') as json_data_file:
    kwargs = json.load(json_data_file)
    for key in kwargs:
        config[key] = kwargs[key]
csrf = CSRFProtect(app)
#this need to set up as ENV variable to run at local
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
####################################################

#Setting for sending email by Gmail API
CLIENT_SECRET_FILE = 'credentials.json'
API_NAME = 'gmail'
API_VERSION = 'v1'
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

service = Create_Service(app.config['EMAIL_HOST'], app.config['EMAIL_PORT'], CLIENT_SECRET_FILE, API_NAME, API_VERSION, SCOPES)

#Established database connection
mysql_string = app.config['SQLALCHEMY_DATABASE_URI']
engine = create_engine(mysql_string, pool_pre_ping=True, echo=False,
                       pool_size=app.config['POOL_SIZE'], pool_recycle=app.config['POOL_RECYCLE'])
#Create database session
sessionFactory = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('login'), code=302)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('index.html')
    session = sessionFactory()
    username = request.form.get('username')
    password = request.form.get('password')
    try:
        getUser = session.query(User).filter(User.username == username).one()
    except Exception as e:
        print('Exception occurred: {}'.format(str(e)))
        session.close()
        return render_template('redirect.html', redirect=url_for('login'), msg='User not found', status=False)
    if getUser.check_password(password):
        session.close()
        return redirect('https://www.viact.ai/', code=302)
    session.close()
    return render_template('redirect.html', redirect=url_for('login'), msg='Wrong username or password', status=False)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    session = sessionFactory()
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_pwd = request.form.get('confirm')
    if password == confirm_pwd:
        try:
            checkUsername = session.query(User).filter(User.username == username).first()
            checkEmail = session.query(User).filter(User.email == email).first()
            if checkEmail is not None:
                session.close()
                return render_template('redirect.html', redirect=url_for('signup'), msg='Email already registered', status=False)
            if checkUsername is not None:
                session.close()
                return render_template('redirect.html', redirect=url_for('signup'), msg='Username already registered', status=False)
            addUser = User(username=username, email=email)
            addUser.passwordMode(password)
            session.add(addUser)
            session.commit()
            return render_template('redirect.html', redirect=url_for('login'), msg='Back to login page', status=True)
        except Exception as e:
            print('Exception occurred: {}'.format(str(e)))
            session.close()
            return render_template('redirect.html', redirect=url_for('signup'), msg='Exception occurred', status=False)
    session.close()
    return render_template('redirect.html', redirect=url_for('login'), msg='Password not match', status=False)


@app.route('/forgotpassword', methods=['GET','POST'])
def forgotpassword():
    if request.method == 'GET':
        return render_template('forgot.html')
    session = sessionFactory()
    email = request.form.get('email')
    try:
        checkEmail = session.query(User).filter(User.email==email).first()
        if checkEmail is not None:
            verify_code = checkEmail.veifiedCode()
            session.add(checkEmail)
            session.commit()
            emailMsg = 'Your verification code is: {}'.format(str(verify_code))
            mimeMessage = MIMEMultipart()
            mimeMessage['to'] = 'rintran1307@gmail.com'
            mimeMessage['subject'] = 'Verification Code'
            mimeMessage.attach(MIMEText(emailMsg, 'plain'))
            raw_string = base64.urlsafe_b64encode(mimeMessage.as_bytes()).decode()
            message = service.users().messages().send(userId='me', body={'raw': raw_string}).execute()
            return redirect('/login', code=302)
        else:
            return render_template('redirect.html', redirect=url_for('signup'), msg='Email not found',
                                   status=False)
    except Exception as e:
        print('Exception occurred: {}'.format(str(e)))
        session.close()
        return render_template('redirect.html', redirect=url_for('signup'), msg='Exception occurred', status=False)

@app.route("/passchange", methods=['GET', 'POST'])
def passchange():
    if request.method == 'GET':
        return render_template('verify.html')
    session = sessionFactory()
    verified_code = request.form.get('verified')
    new_pwd = request.form.get('new_pwd')
    confirm_pwd = request.form.get('confirm_pwd')
    if new_pwd == confirm_pwd:
        checkVerificationCode = session.query(User).filter(User.verified == verified_code).first()
        if checkVerificationCode is not None:
            checkVerificationCode.passwordMode(new_pwd)
            session.add(checkVerificationCode)
            session.commit()
            session.close()
            return render_template('redirect.html', redirect=url_for('login'), msg='Change successful password',
                                   status=True)
        else:
            session.close()
            return render_template('redirect.html', redirect=url_for('passchange'), msg='Verfied Code not right',
                                   status=False)
    else:
        session.close()
        return render_template('redirect.html', redirect=url_for('passchange'), msg='Password not matched',
                               status=False)

@app.route("/googlelogin")
def googlelogin():
    try:
        flow = Flow.from_client_config(
            client_config=config,
            scopes=["https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email", "openid"],
            redirect_uri=app.config['GOOGLE_REDIRECT_URI']
        )
        authorization_url, state = flow.authorization_url()
        flask.session['state'] = state
        resp = make_response(redirect(authorization_url))
        return resp
    except Exception as e:
        return render_template('redirect.html', msg='Exception occurred: {}'.format(str(e)), redirect="/" , status=False)

@app.route('/gCallback')
def callback():
    try:
        session = sessionFactory()
        state = flask.session['state']
        flow = Flow.from_client_config(
            client_config=config,
            scopes=["https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/userinfo.email", "openid"],
            redirect_uri=app.config['GOOGLE_REDIRECT_URI'],
            state=state
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=app.config['GOOGLE_CLIENT_ID']
        )
        addUser = User(username=id_info.get("name"), email=id_info.get("email"))
        session.add(addUser)
        session.commit()
        session.close()
        return redirect("https://www.google.com.vn/")
    except Exception as e:
        return render_template('redirect.html', msg='Exception occurred: {}'.format(str(e)), redirect="/", status=False)



@app.route('/testTemplate', methods=['GET'])
def test():
    return render_template('index.html')


if __name__ == '__main__':
    app.run()
