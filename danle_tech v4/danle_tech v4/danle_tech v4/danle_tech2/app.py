"""
PARTE 1/3 - Imports, Configurações e Helpers
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import mysql.connector
from mysql.connector import Error
from config import DB_CONFIG, SECRET_KEY
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import qrcode
from io import BytesIO
import os
from werkzeug.utils import secure_filename
import base64

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Upload folder
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'images')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

# ----------------- Helpers -----------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user'):
            flash('Faça login para acessar esta página.', 'warning')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user'):
            flash('Faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        if not session['user'].get('is_admin'):
            flash('Acesso negado: área administrativa.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def log_action(user_id, action, details=''):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO logs (user_id, action, details) VALUES (%s,%s,%s)", (user_id, action, details))
        conn.commit()
    except Exception as e:
        print('Log error:', e)
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# ----------------- Rotas Básicas -----------------
@app.route('/')
def index():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products ORDER BY created_at DESC LIMIT 20")
    products = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('index.html', products=products)

@app.route('/produto/<int:product_id>')
def product(product_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()
    if not product:
        flash('Produto não encontrado.', 'warning')
        return redirect(url_for('index'))
    return render_template('product.html', product=product)

@app.route('/categoria/<string:name>')
def category(name):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products WHERE category = %s ORDER BY created_at DESC", (name,))
    products = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('category.html', products=products, category_name=name)

# ----------------- Autenticação -----------------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        
        if not name or not email or not password:
            flash('Preencha todos os campos.', 'warning')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('A senha deve ter no mínimo 6 caracteres.', 'warning')
            return redirect(url_for('register'))
        
        pw_hash = generate_password_hash(password)
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO users (name, email, password_hash, is_admin) VALUES (%s,%s,%s,%s)",
                        (name, email, pw_hash, 0))
            conn.commit()
            user_id = cur.lastrowid
            log_action(user_id, 'register', f'Usuário {email} registrado')
            flash('Cadastro realizado com sucesso. Faça login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('E-mail já cadastrado.', 'danger')
        except Exception as e:
            flash('Erro ao cadastrar: ' + str(e), 'danger')
        finally:
            try:
                cur.close()
                conn.close()
            except:
                pass
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Preencha todos os campos.', 'warning')
            return redirect(url_for('login'))

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user'] = {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'is_admin': bool(user['is_admin'])
            }

            log_action(user['id'], 'login', f'Login realizado')
            flash('Login efetuado com sucesso.', 'success')

            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            
            if session['user']['is_admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Email ou senha incorretos.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user', {}).get('id')
    if user_id:
        log_action(user_id, 'logout', 'Logout realizado')
    
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('index'))

# ----------------- Carrinho -----------------
@app.route('/cart')
def cart():
    cart = session.get('cart', [])
    if not cart:
        return render_template('cart.html', items=[], total=0)

    ids = [int(item['id']) for item in cart]
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    query = "SELECT id, name, price FROM products WHERE id IN (%s)" % (','.join(['%s']*len(ids)))
    cur.execute(query, tuple(ids))
    products = {p['id']: p for p in cur.fetchall()}
    cur.close()
    conn.close()

    items = []
    total = 0.0
    for item in cart:
        pid = int(item['id'])
        qty = int(item.get('qty', 1))
        prod = products.get(pid)
        if not prod:
            continue
        price = float(prod['price'])
        subtotal = qty * price
        total += subtotal
        items.append({'product': prod, 'qty': qty, 'subtotal': subtotal})

    return render_template('cart.html', items=items, total=total)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    qty = int(request.form.get('qty', 1))
    
    if qty <= 0:
        flash('Quantidade inválida.', 'warning')
        return redirect(request.referrer or url_for('index'))

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, name, price, stock FROM products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()

    if not product:
        flash('Produto não encontrado.', 'danger')
        return redirect(url_for('index'))
    
    if product['stock'] < qty:
        flash(f'Estoque insuficiente. Disponível: {product["stock"]} unidades.', 'warning')
        return redirect(request.referrer or url_for('index'))

    cart = session.get('cart', [])
    found = False
    for item in cart:
        if int(item['id']) == int(product_id):
            new_qty = int(item.get('qty', 0)) + qty
            if new_qty > product['stock']:
                flash(f'Estoque insuficiente. Disponível: {product["stock"]} unidades.', 'warning')
                return redirect(request.referrer or url_for('index'))
            item['qty'] = new_qty
            found = True
            break

    if not found:
        cart.append({
            'id': int(product['id']),
            'name': product['name'],
            'price': float(product['price']),
            'qty': qty
        })

    session['cart'] = cart
    flash('Produto adicionado ao carrinho.', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/cart/remove/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    cart = session.get('cart', [])
    cart = [item for item in cart if int(item['id']) != int(product_id)]
    session['cart'] = cart
    flash('Produto removido do carrinho.', 'info')
    return redirect(url_for('cart'))

@app.route('/cart/update/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    qty = int(request.form.get('qty', 1))
    
    if qty <= 0:
        return remove_from_cart(product_id)
    
    cart = session.get('cart', [])
    for item in cart:
        if int(item['id']) == int(product_id):
            item['qty'] = qty
            break
    
    session['cart'] = cart
    flash('Carrinho atualizado.', 'success')
    return redirect(url_for('cart'))

# Continue na Parte 2...
"""
PARTE 2/3 - Checkout, Pedidos, Perfil e Manutenção
Cole este código após a Parte 1
"""

# ----------------- Checkout -----------------
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart = session.get('cart', [])
    if not cart:
        flash('Seu carrinho está vazio.', 'warning')
        return redirect(url_for('cart'))

    payment_method = request.form.get('payment_method') or 'dinheiro'

    ids = [int(item['id']) for item in cart]
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    if not ids:
        flash('Seu carrinho está vazio.', 'warning')
        cur.close()
        conn.close()
        return redirect(url_for('cart'))

    query = "SELECT id, price, stock FROM products WHERE id IN (%s)" % (','.join(['%s'] * len(ids)))
    cur.execute(query, tuple(ids))
    products = {p['id']: {'price': float(p['price']), 'stock': int(p['stock'])} for p in cur.fetchall()}

    # Verifica estoque e produtos existentes
    updated_cart = []
    total = 0.0
    stock_error = False
    
    for item in cart:
        pid = int(item['id'])
        qty = int(item.get('qty', 1))
        
        if pid not in products:
            flash(f"O produto com ID {pid} não existe mais.", "warning")
            continue
        
        if products[pid]['stock'] < qty:
            flash(f"Estoque insuficiente para o produto {item.get('name', 'ID ' + str(pid))}.", "warning")
            stock_error = True
            continue
        
        price = products[pid]['price']
        total += price * qty
        updated_cart.append(item)

    if len(updated_cart) != len(cart):
        session['cart'] = updated_cart
        cur.close()
        conn.close()
        if stock_error:
            flash("Alguns produtos têm estoque insuficiente.", "danger")
        return redirect(url_for('cart'))

    if not updated_cart:
        flash('Seu carrinho está vazio.', 'warning')
        cur.close()
        conn.close()
        return redirect(url_for('cart'))

    # Cria pedido
    cur2 = conn.cursor()
    cur2.execute(
        "INSERT INTO orders (user_id, total, payment_method, status) VALUES (%s, %s, %s, %s)",
        (session['user']['id'], total, payment_method, 'pendente')
    )
    order_id = cur2.lastrowid

    # Insere itens e atualiza estoque
    for item in updated_cart:
        pid = int(item['id'])
        qty = int(item['qty'])
        price = products[pid]['price']
        
        cur2.execute(
            "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (%s,%s,%s,%s)",
            (order_id, pid, qty, price)
        )
        
        # Atualiza estoque
        cur2.execute(
            "UPDATE products SET stock = stock - %s WHERE id = %s",
            (qty, pid)
        )

    conn.commit()
    log_action(session['user']['id'], 'checkout', f'Pedido {order_id} criado')
    cur2.close()
    cur.close()
    conn.close()
    session['cart'] = []

    if payment_method == 'pix':
        flash('Pedido criado! Vá para o pagamento via Pix.', 'info')
        return redirect(url_for('pix_payment', order_id=order_id))

    flash('Compra finalizada com sucesso!', 'success')
    return redirect(url_for('confirmed', order_id=order_id))

# ----------------- Pedidos -----------------
@app.route('/orders')
@login_required
def orders():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE user_id = %s ORDER BY created_at DESC", 
                (session['user']['id'],))
    orders = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('orders.html', orders=orders)

@app.route('/history')
@login_required
def history():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, total, payment_method, status, created_at
        FROM orders
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (session['user']['id'],))
    orders = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('history.html', title='Histórico de Compras', orders=orders)

@app.route('/confirmed/<int:order_id>')
@login_required
def confirmed(order_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", 
                (order_id, session['user']['id']))
    order = cur.fetchone()
    cur.close()
    conn.close()
    if not order:
        flash('Pedido não encontrado.', 'danger')
        return redirect(url_for('index'))
    return render_template('confirmed.html', order=order)

# ----------------- Pagamento Pix -----------------
@app.route('/pix_payment/<int:order_id>')
@login_required
def pix_payment(order_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", 
                (order_id, session['user']['id']))
    order = cur.fetchone()
    cur.close()
    conn.close()
    
    if not order:
        flash('Pedido não encontrado.', 'danger')
        return redirect(url_for('index'))

    pix_data = f"pix://pagamento?valor={order['total']:.2f}&pedido={order_id}"
    qr = qrcode.make(pix_data)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('pix_payment.html', order=order, qr_b64=qr_b64)

@app.route('/confirm_pix/<int:order_id>', methods=['POST'])
@login_required
def confirm_pix(order_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE id=%s AND user_id=%s", 
                (order_id, session['user']['id']))
    order = cur.fetchone()
    
    if not order:
        cur.close()
        conn.close()
        flash("Pedido não encontrado.", "danger")
        return redirect(url_for('index'))

    cur2 = conn.cursor()
    cur2.execute("UPDATE orders SET status='concluido' WHERE id=%s", (order_id,))
    conn.commit()
    log_action(session['user']['id'], 'confirm_pix', f'Pedido {order_id}')
    cur2.close()
    cur.close()
    conn.close()

    flash("Pagamento confirmado com sucesso!", "success")
    return redirect(url_for('confirmed', order_id=order_id))

@app.route('/qrcode/<path:data>')
def generate_qrcode(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=8,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

# ----------------- Perfil do Usuário -----------------
@app.route('/profile')
@login_required
def profile():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM maintenance WHERE user_id = %s ORDER BY created_at DESC", 
                (session['user']['id'],))
    maints = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('profile.html', maintenances=maints)

@app.route('/profile/change_password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if not current or not new_pw or not confirm_pw:
            flash('Preencha todos os campos.', 'warning')
            return redirect(url_for('change_password'))

        if len(new_pw) < 6:
            flash('A nova senha deve ter no mínimo 6 caracteres.', 'warning')
            return redirect(url_for('change_password'))

        if new_pw != confirm_pw:
            flash('A nova senha e a confirmação não coincidem.', 'danger')
            return redirect(url_for('change_password'))

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT password_hash FROM users WHERE id = %s", (session['user']['id'],))
        user = cur.fetchone()

        if not user or not check_password_hash(user['password_hash'], current):
            flash('Senha atual incorreta.', 'danger')
            cur.close()
            conn.close()
            return redirect(url_for('change_password'))

        hashed = generate_password_hash(new_pw)
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed, session['user']['id']))
        conn.commit()
        log_action(session['user']['id'], 'change_password', 'Senha alterada')
        cur.close()
        conn.close()

        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')

# ----------------- Manutenção -----------------
@app.route('/maintenance/request', methods=['GET','POST'])
@login_required
def request_maintenance():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        desc = request.form.get('description','').strip()
        
        if not title or not desc:
            flash('Preencha título e descrição.', 'warning')
            return redirect(url_for('request_maintenance'))
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO maintenance (user_id,title,description,status) VALUES (%s,%s,%s,%s)",
                    (session['user']['id'], title, desc, 'pendente'))
        conn.commit()
        cur.close()
        conn.close()
        log_action(session['user']['id'], 'request_maintenance', title)
        flash('Solicitação enviada com sucesso.', 'success')
        return redirect(url_for('profile'))
    return render_template('request_maintenance.html')

# ----------------- Chat -----------------
@app.route('/chat')
@login_required
def chat():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT cm.*, u.name AS user_name
        FROM chat_messages cm
        JOIN users u ON cm.user_id = u.id
        ORDER BY cm.created_at ASC
        LIMIT 100
    """)
    messages = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('chat.html', messages=messages)

@app.route('/chat/send', methods=['POST'])
@login_required
def send_chat():
    message = request.form.get('message','').strip()
    if not message:
        flash('Digite uma mensagem antes de enviar.', 'warning')
        return redirect(url_for('chat'))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO chat_messages (user_id, user_name, message) VALUES (%s,%s,%s)",
                (session['user']['id'], session['user']['name'], message))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('chat'))

# Continue na Parte 3...
"""
PARTE 3/3 - Painel Administrativo e Inicialização
Cole este código após a Parte 2
"""

# ----------------- Admin Panel -----------------
@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin_panel.html', title='Painel Administrativo')

# ----------------- Admin - Produtos -----------------
@app.route('/admin/products')
@admin_required
def admin_products():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products ORDER BY id DESC")
    products = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_products.html', products=products)

@app.route('/admin/products/create', methods=['POST'])
@admin_required
def admin_create_product():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    price = request.form.get('price', 0)
    stock = request.form.get('stock', 0)
    category = request.form.get('category', '').strip()
    
    if not name or not price:
        flash('Nome e preço são obrigatórios.', 'warning')
        return redirect(url_for('admin_products'))
    
    try:
        price = float(price)
        stock = int(stock)
    except ValueError:
        flash('Preço ou estoque inválido.', 'warning')
        return redirect(url_for('admin_products'))

    image_file = request.files.get('image_file')
    image_url = request.form.get('image_url') or None
    image_filename = None

    if image_file and image_file.filename and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        image_filename = filename

    final_image = image_filename if image_filename else image_url

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (name, description, price, stock, category, image_url)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (name, description, price, stock, category, final_image))
    conn.commit()
    log_action(session['user']['id'], 'create_product', name)
    cursor.close()
    conn.close()

    flash('Produto adicionado com sucesso!', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/products/edit/<int:product_id>', methods=['POST'])
@admin_required
def admin_edit_product(product_id):
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    price = request.form.get('price', 0)
    stock = request.form.get('stock', 0)
    category = request.form.get('category', '').strip()
    
    try:
        price = float(price)
        stock = int(stock)
    except ValueError:
        flash('Preço ou estoque inválido.', 'warning')
        return redirect(url_for('admin_products'))

    image_file = request.files.get('image_file')
    image_url = request.form.get('image_url') or None
    image_filename = image_url

    if image_file and image_file.filename and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        image_filename = filename

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE products 
        SET name=%s, description=%s, price=%s, stock=%s, category=%s, image_url=%s
        WHERE id=%s
    """, (name, description, price, stock, category, image_filename, product_id))
    db.commit()
    log_action(session['user']['id'], 'edit_product', f'{product_id} - {name}')
    cursor.close()
    db.close()

    flash('Produto atualizado com sucesso!', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM order_items WHERE product_id = %s", (product_id,))
        cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
        conn.commit()
        log_action(session['user']['id'], 'delete_product', f'{product_id}')
        flash('Produto excluído com sucesso.', 'info')
    except mysql.connector.IntegrityError as e:
        conn.rollback()
        flash('Não foi possível excluir o produto: ' + str(e), 'danger')
    except Exception as e:
        conn.rollback()
        flash('Erro ao excluir produto: ' + str(e), 'danger')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_products'))

@app.route('/admin/products/update_all', methods=['POST'])
@admin_required
def admin_update_all_products():
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("SELECT id FROM products")
        ids = [str(r[0]) for r in cur.fetchall()]

        for pid in ids:
            name = request.form.get(f"name_{pid}")
            description = request.form.get(f"description_{pid}")
            price = request.form.get(f"price_{pid}")
            stock = request.form.get(f"stock_{pid}")
            category = request.form.get(f"category_{pid}")

            image_file = request.files.get(f"image_file_{pid}")
            image_url = None

            if image_file and image_file.filename and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image_url = filename

            cur.execute("""
                UPDATE products
                SET name=%s, description=%s, price=%s, stock=%s, category=%s,
                    image_url=COALESCE(%s, image_url)
                WHERE id=%s
            """, (name, description, price, stock, category, image_url, pid))

        conn.commit()
        log_action(session['user']['id'], 'update_all_products', 'Atualização em massa')
        flash("Produtos atualizados com sucesso!", "success")

    except Exception as e:
        conn.rollback()
        flash("Erro ao atualizar produtos: " + str(e), "danger")

    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_products'))

# ----------------- Admin - Manutenção -----------------
@app.route('/admin/maintenance')
@admin_required
def admin_maintenance():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT m.*, u.email AS user_email, u.name AS user_name 
        FROM maintenance m 
        JOIN users u ON m.user_id = u.id 
        ORDER BY m.created_at DESC
    """)
    items = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_maintenance.html', maintenances=items)

@app.route('/admin/maintenance/update/<int:mid>', methods=['POST'])
@admin_required
def admin_update_maintenance(mid):
    status = request.form.get('status','pendente')
    expected_delivery = request.form.get('expected_delivery') or None
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE maintenance SET status=%s, expected_delivery=%s WHERE id=%s", 
                (status, expected_delivery, mid))
    conn.commit()
    log_action(session['user']['id'], 'update_maintenance', f'{mid} -> {status}')
    cur.close()
    conn.close()
    flash('Manutenção atualizada.', 'success')
    return redirect(url_for('admin_maintenance'))

# ----------------- Admin - Pedidos -----------------
@app.route("/admin/orders")
@admin_required
def admin_orders():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT 
            o.id AS order_id,
            o.total,
            o.payment_method,
            o.status,
            o.created_at,
            u.name AS user_name,
            u.id AS user_id
        FROM orders o
        JOIN users u ON o.user_id = u.id
        ORDER BY o.created_at DESC
    """)
    orders = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("admin_orders.html", orders=orders)

@app.route('/admin/orders/update/<int:order_id>', methods=['POST'])
@admin_required
def admin_update_order(order_id):
    status = request.form.get('status', 'pendente')
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE orders SET status=%s WHERE id=%s", (status, order_id))
    conn.commit()
    log_action(session['user']['id'], 'update_order', f'Pedido {order_id} -> {status}')
    cur.close()
    conn.close()
    
    flash('Status do pedido atualizado.', 'success')
    return redirect(url_for('admin_orders'))

# ----------------- Utilitário: Criar Admin -----------------
@app.route('/create_admin', methods=['POST'])
def create_admin():
    secret = request.form.get('secret')
    if secret != 'CREATE_ADMIN_SECRET':
        return 'Forbidden', 403
    
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not name or not email or not password:
        return 'Campos obrigatórios faltando', 400
    
    hashed = generate_password_hash(password)
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (name,email,password_hash,is_admin) VALUES (%s,%s,%s,%s)", 
                   (name, email, hashed, 1))
        conn.commit()
        log_action(None, 'create_admin', f'Admin {email} criado')
        return 'Admin criado com sucesso'
    except mysql.connector.IntegrityError:
        return 'Email já cadastrado', 400
    except Exception as e:
        return str(e), 400
    finally:
        cur.close()
        conn.close()

# ----------------- Error Handlers -----------------
@app.errorhandler(404)
def not_found(e):
    flash('Página não encontrada.', 'warning')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(e):
    flash('Erro interno do servidor. Tente novamente.', 'danger')
    return redirect(url_for('index'))

# ----------------- Inicialização -----------------
if __name__ == '__main__':
    app.run(debug=True)