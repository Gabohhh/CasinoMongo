from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import os
import bcrypt

# Configuración de la aplicación Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Clave secreta para las sesiones (en producción usa una fija y segura)

# Conexión a MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client.casino_db
users_collection = db.users
transactions_collection = db.transactions

# =============================================
# Funciones de seguridad (hasheo y verificación)
# =============================================
def hash_password(password):
    """Genera un hash seguro de la contraseña usando bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(hashed_password, user_password):
    """Verifica si la contraseña coincide con el hash almacenado."""
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# =============================================
# Creación del usuario administrador por defecto
# =============================================
ADMIN_EMAIL = "admin@casino.com"
ADMIN_PLAIN_PASSWORD = "Admin123!"  # Contraseña temporal (se hashea antes de guardar)

if not users_collection.find_one({"email": ADMIN_EMAIL}):
    hashed_admin_pw = hash_password(ADMIN_PLAIN_PASSWORD)
    admin_user = {
        "email": ADMIN_EMAIL,
        "password": hashed_admin_pw,
        "phone": "+56912345678",
        "role": "admin",
        "balance": 0,
        "created_at": datetime.now(),
        "last_login": None,
        "active": True
    }
    users_collection.insert_one(admin_user)

# =============================================
# Rutas de la aplicación
# =============================================
@app.route('/')
def home():
    """Redirige al login o al dashboard según la sesión."""
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Maneja el inicio de sesión de usuarios."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = users_collection.find_one({"email": email})
        
        # Verificar credenciales
        if user and check_password(user['password'], password):
            session['user'] = {
                'id': str(user['_id']),
                'email': user['email'],
                'role': user['role']
            }
            # Actualizar última conexión
            users_collection.update_one(
                {"_id": user['_id']},
                {"$set": {"last_login": datetime.now()}}
            )
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Muestra el panel principal según el rol del usuario."""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_data = users_collection.find_one({"_id": ObjectId(session['user']['id'])})
    
    if user_data['role'] == 'admin':
        return render_template('dashboard.html', user=user_data, is_admin=True)
    else:
        return render_template('dashboard.html', user=user_data, is_admin=False)


@app.route('/create-account', methods=['GET', 'POST'])
def create_account():
    """Permite a los administradores crear nuevas cuentas."""
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone')
        role = request.form.get('role')
        
        # Validaciones básicas
        if len(password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres', 'danger')
            return redirect(url_for('create_account'))
        
        if users_collection.find_one({"email": email}):
            flash('El correo electrónico ya está registrado', 'danger')
            return redirect(url_for('create_account'))
        
        # Crear el nuevo usuario con contraseña hasheada
        new_user = {
            "email": email,
            "password": hash_password(password),
            "phone": phone,
            "role": role,
            "balance": 100000 if role == 'trial' else 0,
            "created_at": datetime.now(),
            "last_login": None,
            "active": True
        }
        
        users_collection.insert_one(new_user)
        flash('Cuenta creada exitosamente', 'success')
        return redirect(url_for('accounts'))
    
    return render_template('create_account.html')

@app.route('/account-details/<user_id>')
def account_details(user_id):
    """Muestra detalles de una cuenta específica."""
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    transactions = list(transactions_collection.find({
        "$or": [
            {"from_user": user_id},
            {"to_user": user_id}
        ]
    }))
    
    return render_template('account_details.html', user=user, transactions=transactions)

@app.route('/logout')
def logout():
    """Cierra la sesión del usuario."""
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/edit-account/<user_id>', methods=['GET', 'POST'])
def edit_account(user_id):
    """Permite editar la información de una cuenta existente."""
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    
    if request.method == 'POST':
        # Recopilamos los datos del formulario
        email = request.form.get('email')
        phone = request.form.get('phone')
        role = request.form.get('role')
        active = 'active' in request.form  # Checkbox
        
        # Validación básica
        if users_collection.find_one({"email": email, "_id": {"$ne": ObjectId(user_id)}}):
            flash('El correo electrónico ya está registrado en otra cuenta', 'danger')
            return redirect(url_for('edit_account', user_id=user_id))
        
        # Preparar los datos a actualizar
        update_data = {
            "email": email,
            "phone": phone,
            "role": role,
            "active": active
        }
        
        # Si se proporciona una nueva contraseña, la actualizamos
        new_password = request.form.get('password')
        if new_password and len(new_password) >= 8:
            update_data["password"] = hash_password(new_password)
        
        # Actualizar usuario
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        
        flash('Cuenta actualizada exitosamente', 'success')
        return redirect(url_for('accounts'))
    
    return render_template('edit_account.html', user=user)

@app.route('/toggle-account/<user_id>')
def toggle_account(user_id):
    """Activa o desactiva una cuenta de usuario."""
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    # No permitir desactivar la propia cuenta del administrador
    if user_id == session['user']['id']:
        flash('No puedes desactivar tu propia cuenta', 'danger')
        return redirect(url_for('accounts'))
    
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    new_status = not user['active']
    
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"active": new_status}}
    )
    
    status_msg = "activada" if new_status else "desactivada"
    flash(f'Cuenta {status_msg} exitosamente', 'success')
    return redirect(url_for('accounts'))

@app.route('/delete-account/<user_id>', methods=['POST'])
def delete_account(user_id):
    """Elimina permanentemente una cuenta de usuario."""
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    # No permitir eliminar la propia cuenta del administrador
    if user_id == session['user']['id']:
        flash('No puedes eliminar tu propia cuenta', 'danger')
        return redirect(url_for('accounts'))
    
    # Eliminar el usuario y sus transacciones asociadas
    users_collection.delete_one({"_id": ObjectId(user_id)})
    transactions_collection.delete_many({
        "$or": [
            {"from_user": user_id},
            {"to_user": user_id}
        ]
    })
    
    flash('Cuenta eliminada permanentemente', 'success')
    return redirect(url_for('accounts'))


@app.route('/accounts')
def accounts():
    """List accounts with search and filters"""
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('dashboard'))
    
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = 25
    
    # Get filter parameters
    search_term = request.args.get('search', '').strip()
    role_filter = request.args.get('role', '')
    status_filter = request.args.get('status', '')
    
    # Build MongoDB query
    query = {}
    
    if search_term:
        query['$or'] = [
            {'email': {'$regex': search_term, '$options': 'i'}},
            {'phone': {'$regex': search_term, '$options': 'i'}}
        ]
    
    if role_filter:
        query['role'] = role_filter
    
    if status_filter:
        query['active'] = (status_filter == 'active')
    
    # Get paginated results
    users_cursor = users_collection.find(query).sort('created_at', -1)
    total_users = users_collection.count_documents(query)
    users = list(users_cursor.skip((page - 1) * per_page).limit(per_page))
    
    return render_template(
        'accounts.html',
        users=users,
        page=page,
        per_page=per_page,
        total_users=total_users
    )

# =============================================
# Inicio de la aplicación
# =============================================
if __name__ == '__main__':
    app.run(debug=True)
