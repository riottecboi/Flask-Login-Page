from flask import Flask, render_template, request, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_env import MetaFlaskEnv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datamodel import Base, User

app = Flask(__name__)

class Configuration(metaclass=MetaFlaskEnv):
    SECRET_KEY = "supersecretkey"
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://localhost:3306/testlogin?user=root&password=root'
    POOL_SIZE = 5
    POOL_RECYCLE = 60

try:
    app.config.from_pyfile('settings.cfg')
except FileNotFoundError:
    app.config.from_object(Configuration)

csrf = CSRFProtect(app)

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
        return render_template('redirect.html', redirect=url_for('login'), msg='Not found user', status=False)
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
                return render_template('redirect.html', redirect=url_for('signup'), msg='Email already registered', status=False)
            if checkUsername is not None:
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


@app.route('/testTemplate', methods=['GET'])
def test():
    return render_template('index.html')


if __name__ == '__main__':
    app.run()
