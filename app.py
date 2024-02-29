# Additional imports
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, roles_accepted
import random
from datetime import datetime, timedelta
import secrets

# Initialize Flask app
app = Flask(__name__)

# Configure Flask app
app.config['SECRET_KEY'] = '@Kwanyanya2'  # Set the secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aviator_predictor.db'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt_here'
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False

# Initialize SQLAlchemy database
db = SQLAlchemy(app)

# Initialize Flask-Migrate for database migrations
migrate = Migrate(app, db)

# Define Flask-Security models
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
                       )

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

# Define Flask-Security datastores
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Define Aviator Predictor models
class PredictionWebsite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    url = db.Column(db.String(255), unique=True)
    active = db.Column(db.Boolean(), default=True)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(50), unique=True)
    expiration_date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('tokens', lazy='dynamic'))

# Define routes and views
# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Prediction route
@app.route('/predict')
@login_required
def predict():
    prediction_websites = PredictionWebsite.query.filter_by(active=True).all()
    return render_template('predict.html', prediction_websites=prediction_websites)

# Prediction logic route
@app.route('/predict_result/<int:website_id>')
@login_required
def predict_result(website_id):
    website = PredictionWebsite.query.get_or_404(website_id)
    if website.active:
        if 'token' in request.args:
            token = request.args.get('token')
            if check_token(token):
                prediction = generate_prediction()
                return render_template('predict_result.html', website=website, prediction=prediction)
            else:
                flash('Invalid or expired token', 'danger')
        else:
            flash('Token is required to access this website', 'warning')
    else:
        flash('This website is currently deactivated', 'warning')
    return redirect(url_for('predict'))

# Admin dashboard route
@app.route('/admin/dashboard')
@roles_accepted('admin')
def admin_dashboard():
    prediction_websites = PredictionWebsite.query.all()
    return render_template('admin_dashboard.html', prediction_websites=prediction_websites)

# Add prediction website route
@app.route('/admin/add_website', methods=['GET', 'POST'])
@roles_accepted('admin')
def add_website():
    if request.method == 'POST':
        name = request.form['name']
        url = request.form['url']
        website = PredictionWebsite(name=name, url=url)
        db.session.add(website)
        db.session.commit()
        flash('Website added successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_website.html')

# Activate/deactivate website route
@app.route('/admin/activate_deactivate_website/<int:website_id>')
@roles_accepted('admin')
def activate_deactivate_website(website_id):
    website = PredictionWebsite.query.get_or_404(website_id)
    website.active = not website.active
    db.session.commit()
    flash('Website activated/deactivated successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# Delete website route
@app.route('/admin/delete_website/<int:website_id>')
@roles_accepted('admin')
def delete_website(website_id):
    website = PredictionWebsite.query.get_or_404(website_id)
    db.session.delete(website)
    db.session.commit()
    flash('Website deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# Generate token route
@app.route('/generate_token')
@login_required
def generate_token():
    current_user_token = Token.query.filter_by(user_id=current_user.id).first()
    if current_user_token and current_user_token.expiration_date > datetime.utcnow():
        flash('Token already generated and valid until {}'.format(current_user_token.expiration_date), 'info')
    else:
        token = secrets.token_urlsafe(10)  # Generate a secure token
        expiration_date = datetime.utcnow() + timedelta(days=30)  # Token expiration after 30 days
        new_token = Token(token=token, expiration_date=expiration_date, user_id=current_user.id)
        db.session.add(new_token)
        db.session.commit()
        flash('Token generated successfully and valid until {}'.format(expiration_date), 'success')
    return redirect(url_for('index'))

# Prediction logic function
def generate_prediction():
    return random.randint(1, 100)  # Generate a random number between 1 and 100

# Check token validity function
def check_token(token):
    current_token = Token.query.filter_by(token=token).first()
    if current_token and current_token.expiration_date > datetime.utcnow():
        return True
    return False

# Run Flask app
if __name__ == '__main__':
    app.run(debug=True)
