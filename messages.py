# -*- coding: utf-8 *-*
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form, TextField, Required, PasswordField, SubmitField
from flask.ext.login import (LoginManager, login_required, login_user,
                             logout_user, current_user, UserMixin)
from os import urandom

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.secret_key = urandom(24)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.setup_app(app)

@login_manager.user_loader
def load_user(userid):
    return User.query.get(userid)

### Views ###
@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated():
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(form.username.data, form.email.data, form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('You have registered succesfully.', category='message')
        return redirect('/index')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        login_user(user)
        flash('Logged in succesfully', category='message')
        return redirect(url_for("index"))
    return render_template('login.html', form=form,  errors = form.errors,\
                               next=request.args.get('next'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/')
@app.route('/index')
@login_required
def index():
    topics = Topic.query.order_by(Topic.id.desc())
    return render_template('index.html', topics=topics)

@app.route('/users')
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/new_topic', methods=['GET', 'POST'])
@login_required
def new_topic():
    form = NewTopicForm()
    delete_post_form = DeletePostForm()
    if form.validate_on_submit():
        topic = Topic(form.topic.data, current_user.id)
        db.session.add(topic)
        db.session.commit()
        post = Post(form.post.data, topic.id, \
                        current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Topic added')
        return redirect(url_for('index'))
    return render_template('new_topic.html', form=form, \
                               delete_post_form=delete_post_form)

@app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
@login_required
def topic(topic_id):
    posts = Post.query.filter_by(topic_id=topic_id)
    form = ReplyForm()
    if form.validate_on_submit():
        p = Post(form.post.data, topic_id, current_user.id)
        db.session.add(p)
        db.session.commit()
        return redirect(url_for('topic', topic_id=topic_id))
    return render_template('/posts.html', posts=posts, form=form)

#Testing purposes!!
@app.route('/testuser')
def testuser():
    return render_template('testuser.html', current_user=current_user)
#Testing purposes!!

### Models ###
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(10))
    email = db.Column(db.String(120), unique=True)

    def __init__(self, username, email, password):
        self.username = username
        self.password = password
        self.email = email
    
    def __repr__(self):
        return '<User %r>' % self.username

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.Text)
    create_date = db.Column(db.DateTime)
    
    posted_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    posted_by = db.relationship('User', \
                                    backref=db.backref('topics', \
                                                        lazy='dynamic'))
    
    def __init__(self, topic, user):
        self.topic = topic
        self.create_date = datetime.utcnow()
        self.posted_by_id = user
    def __repr__(self):
        return '<Topic %r>' % self.topic

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.Text)
    post_date = db.Column(db.DateTime)

    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'))
    topic = db.relationship('Topic', \
                                backref=db.backref('posts', lazy='dynamic'))
    posted_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    posted_by = db.relationship('User', \
                                    backref=db.backref('posts', \
                                                        lazy='dynamic'))
    
    def __init__(self, post, topic, user):
        self.post = post
        self.post_date = datetime.utcnow()
        self.topic_id = topic
        self.posted_by_id = user
    def __repr__(self):
        return '<Post %r>' % self.post

### Forms ###
class LoginForm(Form):
    username = TextField("username", validators=[Required()])
    password = PasswordField("password", validators=[Required()])

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if not user:
            flash('Login failed', category='error')
            return False
        return True

class RegisterForm(Form):
    username = TextField("Username", validators=[Required()])
    email = TextField("Email", validators=[Required()])
    password = PasswordField("Password", validators=[Required()])

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False
        username = User.query.filter_by(username=self.username.data).first()
        if username is not None:
            self.username.errors.append('User exists')
            return False
        email  = User.query.filter_by(email=self.email.data).first()
        if email is not None:
            self.email.errors.append('Email exists')
            return False
        return True

class NewTopicForm(Form):
    topic = TextField("Topic", validators=[Required()])
    post = TextField("Message", validators=[Required()])

class ReplyForm(Form):
    post = TextField("Message", validators=[Required()])

class DeletePostForm(Form):
    delete = SubmitField("Delete")

class EditPostForm(Form):
    edit = SubmitField("Edit")

class DeleteTopicForm(Form):
    delete = SubmitField("Delete")
    
if __name__ == '__main__':
    app.run(debug=True)
