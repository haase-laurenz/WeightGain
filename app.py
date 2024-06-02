from flask import Flask, render_template, redirect, url_for, request, flash,session, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, WeightEntry
from flask_debugtoolbar import DebugToolbarExtension
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

app.config.update(
    TEMPLATES_AUTO_RELOAD=True
)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/profile')
@login_required
def profile():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    else:    
        return render_template('profile.html', current_user=current_user)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Login failed. Check your username and password.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256:600000')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('profile'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/market')
def market():
    users = User.query.all()
    return render_template('market.html', users=users)

@app.route('/editProfile', methods=['GET', 'POST'])
def editProfile():
    if request.method == 'POST':
        
        current_user.username = request.form.get('username')
        new_password = request.form.get('password')
        
        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256:600000')
        db.session.commit()
        
        return redirect(url_for('profile'))
        
    return render_template('editProfile.html')

@app.route('/weight_data', methods=['GET', 'POST'])
def weight_data():
    user = current_user
    
    if request.method == 'POST':
        weight = request.form.get('weight')
        new_entry = WeightEntry(weight=weight, user_id=user.id)
        db.session.add(new_entry)
        db.session.commit()        
        
    current_weight=""
    if len(user.weight_entries)>0:
        current_weight = str(user.weight_entries[-1].weight)+" kg."
    else:
        current_weight = "No weight data yet. Add now."
        
    return render_template('weight_data.html', current_weight=current_weight)

@app.route('/weight_dataGraph')
def weight_dataGraph():

    user = current_user  # Beispiel für einen festgelegten Benutzer, ändern Sie dies entsprechend
    entries = [
        {'date': entry.date.isoformat(), 'weight': entry.weight}
        for entry in user.weight_entries
    ]
    return jsonify(entries)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=3000)
