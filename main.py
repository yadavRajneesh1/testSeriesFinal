from flask import Flask, render_template
from flask_wtf import FlaskForm
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


@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template("home.html")


@app.route('/myinfo')
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
        insert_query = '''INSERT INTO public."user"(
        	 "UserEmail", "UserPassword")
        	VALUES (%s,%s);'''
        cursor.execute(insert_query, (name, password))
        connection.commit()
        return render_template("thanks.html", form=login)
    return render_template("signup.html", form=login)


@app.route('/question', methods=['GET', 'POST'])
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
