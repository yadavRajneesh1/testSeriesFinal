from functools import wraps
from flask import Flask, render_template, request, session, flash, url_for
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email
import psycopg2
import json

app = Flask(__name__)
with open("config.json", "r") as f:
    params = json.load(f)['params']

app.secret_key = params['secret_key']

connection = psycopg2.connect(user=params['user'], password=params['password'],
                              host=params['host'], port=params['port'],
                              database=params['database'])
cursor = connection.cursor()


class Login(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Email()])
    password = PasswordField('password', validators=[InputRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Submit')


class Question(FlaskForm):
    question = TextAreaField('question', validators=[InputRequired()])
    option1 = TextAreaField('option1', validators=[InputRequired()])
    option2 = TextAreaField('option2', validators=[InputRequired()])
    option3 = TextAreaField('option3', validators=[InputRequired()])
    option4 = TextAreaField('option4', validators=[InputRequired()])
    submit = SubmitField('Submit')


def login_required(fuct):
    @wraps(fuct)
    def wrap(*args, **kwargs):
        if 'user_id' in session:
            return fuct(*args, **kwargs)
        else:
            flash('You need to login first')
            return redirect(url_for('login'))

    return wrap


@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template("home.html")


@app.route('/myinfo')
@login_required
def Navbar():
    return render_template("myinfo.html")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    login = Login()
    if login.validate_on_submit():
        name = login.username.data
        password = login.password.data
        print(name)
        print(password)
        hassed_password = generate_password_hash(login.password.data, method='sha256')
        insert_query = '''INSERT INTO public."user"(
        "UserEmail", "UserPassword")
        VALUES (%s,%s);'''
        cursor.execute(insert_query, (name, hassed_password))
        connection.commit()
        return render_template("thanks.html", form=login)
    return render_template("signup.html", form=login)


@app.route('/login', methods=['GET', 'POST'])
def login():
    log = Login()
    if request.method == 'POST':
        session.pop('username', None)
        username = request.form['username']
        password = request.form['password']
        print(username)
        print(password)
        # userone = usernew.query.filter_by(UserEmail=username).first()
        select_query = '''SELECT no, "UserEmail", "UserPassword"
	FROM public."user" where "UserEmail"=%s;'''
        cursor.execute(select_query, (username,))
        user_record = cursor.fetchall()
        print(user_record)
        if user_record and check_password_hash(user_record[0][2], password):
            session['user_id'] = user_record[0][1]
            return render_template('home.html')
        return '<h1>Please make sure your credentials your username or password or both are incorrect</h1>'

    return render_template('login.html', form=log)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash("you are logout")
    return render_template('home.html')


@app.route('/question', methods=['GET', 'POST'])
@login_required
def question():
    quest = Question()
    if quest.validate_on_submit():
        insert_query = '''INSERT INTO public."Question"(
        question, option1, option2, option3, option4)
        VALUES (%s,%s,%s,%s,%s);'''
        cursor.execute(insert_query, (
            quest.question.data, quest.option1.data, quest.option2.data, quest.option3.data, quest.option4.data))
        connection.commit()
        return render_template('thanks.html', quest=quest)
        # name = request.form.get('username')
        # return "Form submitted Succesfully  " + login.username.data + " " + login.password.data
    return render_template('question.html', quest=quest)


@app.route('/thanks', methods=['GET', 'POST'])
def thanks():
    return render_template("thanks.html")


if __name__ == '__main__':
    app.run(debug=True)
