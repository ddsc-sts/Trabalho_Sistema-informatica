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
            cur.close(); conn.close()
        except:
            pass

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# ----------------- Routes -----------------
@app.route('/')
def index():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products ORDER BY created_at DESC LIMIT 20")
    products = cur.fetchall()
    cur.close(); conn.close()
    return render_template('index.html', products=products)

# Product details
@app.route('/produto/<int:product_id>')
def product(product_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    cur.close(); conn.close()
    if not product:
        flash('Produto não encontrado.', 'warning')
        return redirect(url_for('index'))
    return render_template('product.html', product=product)

# Register
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        if not name or not email or not password:
            flash('Preencha todos os campos.', 'warning')
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
                cur.close(); conn.close()
            except:
                pass
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower()
        password = request.form.get('password', '')

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close(); conn.close()

        if user and check_password_hash(user['password_hash'], password):
            # ✅ Correto: bloco dentro do IF
            session['user'] = {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'is_admin': bool(user['is_admin'])
            }

            flash('Login efetuado com sucesso.', 'success')

            # 🔹 Se for admin, manda para o painel administrativo
            if session['user']['is_admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Email ou senha incorretos.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')
# ----------------- Cart -----------------
@app.route('/cart')
def cart():
    # cart is a list of dicts: [{'id': int, 'qty': int, 'price': float, 'name': str}, ...]
    cart = session.get('cart', [])
    if not cart:
        return render_template('cart.html', items=[], total=0)

    # Ensure ids are ints and fetch current product info
    ids = [int(item['id']) for item in cart]
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    query = "SELECT id, name, price FROM products WHERE id IN (%s)" % (','.join(['%s']*len(ids)))
    cur.execute(query, tuple(ids))
    products = {p['id']: p for p in cur.fetchall()}
    cur.close(); conn.close()

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

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, name, price FROM products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    cur.close(); conn.close()

    if not product:
        flash('Produto não encontrado.', 'danger')
        return redirect(url_for('index'))

    cart = session.get('cart', [])
    found = False
    for item in cart:
        if int(item['id']) == int(product_id):
            item['qty'] = int(item.get('qty', 0)) + qty
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

# ----------------- Checkout -----------------
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart = session.get('cart', [])
    if not cart:
        flash('Seu carrinho está vazio.', 'warning')
        return redirect(url_for('cart'))

    payment_method = request.form.get('payment_method') or 'dinheiro'

    # --- Verifica se produtos do carrinho ainda existem no banco ---
    ids = [int(item['id']) for item in cart]
    conn = get_db()
    cur = conn.cursor(dictionary=True)

    if not ids:
        flash('Seu carrinho está vazio.', 'warning')
        cur.close(); conn.close()
        return redirect(url_for('cart'))

    query = "SELECT id, price FROM products WHERE id IN (%s)" % (','.join(['%s'] * len(ids)))
    cur.execute(query, tuple(ids))
    products = {p['id']: float(p['price']) for p in cur.fetchall()}

    # Remove produtos que não existem mais
    updated_cart = []
    for item in cart:
        pid = int(item['id'])
        if pid in products:
            updated_cart.append(item)
        else:
            flash(f"O produto com ID {pid} não existe mais. Ele foi removido do carrinho.", "warning")

    if len(updated_cart) != len(cart):
        session['cart'] = updated_cart
        cur.close(); conn.close()
        flash("Alguns produtos foram removidos do carrinho por não estarem mais disponíveis.", "danger")
        return redirect(url_for('cart'))

    # --- Calcula total baseado nos preços atuais do DB ---
    total = 0.0
    for item in updated_cart:
        pid = int(item['id'])
        qty = int(item.get('qty', 1))
        price = products.get(pid, float(item.get('price', 0)))
        total += price * qty

    # --- Cria pedido ---
    cur2 = conn.cursor()
    cur2.execute(
        "INSERT INTO orders (user_id, total, payment_method, status) VALUES (%s, %s, %s, %s)",
        (session['user']['id'], total, payment_method, 'pendente')
    )
    order_id = cur2.lastrowid

    # --- Insere itens ---
    for item in updated_cart:
        pid = int(item['id'])
        qty = int(item['qty'])
        price = products.get(pid, float(item.get('price', 0)))
        cur2.execute(
            "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (%s,%s,%s,%s)",
            (order_id, pid, qty, price)
        )

    conn.commit()
    cur2.close(); cur.close(); conn.close()
    session['cart'] = []

    # --- Redireciona conforme método de pagamento ---
    if payment_method == 'pix':
        flash('Pedido criado! Vá para o pagamento via Pix.', 'info')
        return redirect(url_for('pix_payment', order_id=order_id))

    flash('Compra finalizada com sucesso!', 'success')
    return redirect(url_for('confirmed', order_id=order_id))



# ----------------- Maintenance -----------------
@app.route('/maintenance/request', methods=['GET','POST'])
@login_required
def request_maintenance():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        desc = request.form.get('description','').strip()
        if not title or not desc:
            flash('Preencha título e descrição.', 'warning')
            return redirect(url_for('request_maintenance'))
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO maintenance (user_id,title,description,status) VALUES (%s,%s,%s,%s)",
                    (session['user']['id'], title, desc, 'pendente'))
        conn.commit()
        cur.close(); conn.close()
        log_action(session['user']['id'], 'request_maintenance', title)
        flash('Solicitação enviada com sucesso.', 'success')
        return redirect(url_for('profile'))
    return render_template('request_maintenance.html')

# ----------------- Profile -----------------
@app.route('/profile')
@login_required
def profile():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM maintenance WHERE user_id = %s ORDER BY created_at DESC", (session['user']['id'],))
    maints = cur.fetchall()
    cur.close(); conn.close()
    return render_template('profile.html', maintenances=maints)

# ----------------- Admin -----------------
@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin_panel.html')

@app.route('/admin/products')
@admin_required
def admin_products():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products ORDER BY id DESC")
    products = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_products.html', products=products)

# create product (upload or URL)
@app.route('/admin/products/create', methods=['POST'])
@admin_required
def admin_create_product():
    name = request.form['name']
    description = request.form.get('description', '')
    price = float(request.form['price'])
    stock = int(request.form['stock'])

    image_file = request.files.get('image_file')
    image_url = request.form.get('image_url') or None
    image_filename = None

    if image_file and image_file.filename and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        image_filename = filename

    final_image = image_filename if image_filename else (image_url if image_url else None)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (name, description, price, stock, image_url)
        VALUES (%s, %s, %s, %s, %s)
    """, (name, description, price, stock, final_image))
    conn.commit()
    cursor.close(); conn.close()

    flash('Produto adicionado com sucesso!', 'success')
    return redirect(url_for('admin_products'))

# edit single product (used by form that edits one product)
@app.route('/admin/products/edit/<int:product_id>', methods=['POST'])
@admin_required
def admin_edit_product(product_id):
    name = request.form['name']
    price = float(request.form.get('price', 0))
    stock = int(request.form.get('stock', 0))

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
        SET name=%s, price=%s, stock=%s, image_url=%s
        WHERE id=%s
    """, (name, price, stock, image_filename, product_id))
    db.commit()
    cursor.close(); db.close()

    flash('Produto atualizado com sucesso!', 'success')
    return redirect(url_for('admin_products'))

# 🔹 Rota: excluir produto (Admin)
@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    conn = get_db()
    cur = conn.cursor()
    try:
        # 1) remover order_items que usam esse produto (se existir)
        cur.execute("DELETE FROM order_items WHERE product_id = %s", (product_id,))
        # 2) remover o produto
        cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
        conn.commit()

        # log (tenta pegar user id da sessão)
        try:
            user_id = session['user']['id']
        except Exception:
            user_id = None
        log_action(user_id, 'delete_product', f'{product_id}')

        flash('Produto excluído com sucesso (itens de pedido relacionados também removidos).', 'info')
    except mysql.connector.IntegrityError as e:
        conn.rollback()
        flash('Não foi possível excluir o produto por restrição de integridade: ' + str(e), 'danger')
    except Exception as e:
        conn.rollback()
        flash('Erro ao excluir produto: ' + str(e), 'danger')
    finally:
        try:
            cur.close(); conn.close()
        except:
            pass

    return redirect(url_for('admin_products'))







# Admin maintenance and orders (same as before)
@app.route('/admin/maintenance')
@admin_required
def admin_maintenance():
    conn = get_db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT m.*, u.email AS user_email, u.name AS user_name FROM maintenance m JOIN users u ON m.user_id = u.id ORDER BY m.created_at DESC")
    items = cur.fetchall()
    cur.close(); conn.close()
    return render_template('admin_maintenance.html', maintenances=items)

@app.route('/admin/maintenance/update/<int:mid>', methods=['POST'])
@admin_required
def admin_update_maintenance(mid):
    status = request.form.get('status','pendente')
    expected_delivery = request.form.get('expected_delivery') or None
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE maintenance SET status=%s, expected_delivery=%s WHERE id=%s", (status, expected_delivery, mid))
    conn.commit()
    log_action(session['user']['id'], 'update_maintenance', f'{mid} -> {status}')
    cur.close(); conn.close()
    flash('Manutenção atualizada.', 'success')
    return redirect(url_for('admin_maintenance'))



# create_admin utility (keep as you had)
@app.route('/create_admin', methods=['POST'])
def create_admin():
    secret = request.form.get('secret')
    if secret != 'CREATE_ADMIN_SECRET':
        return 'Forbidden', 403
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    hashed = generate_password_hash(password)
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (name,email,password_hash,is_admin) VALUES (%s,%s,%s,%s)", (name,email,hashed,1))
        conn.commit()
        return 'Admin criado'
    except Exception as e:
        return str(e), 400
    finally:
        cur.close(); conn.close()

# QR code endpoint (raw image)
@app.route('/qrcode/<path:data>')
def generate_qrcode(data):
    # data may be urlencoded; we'll just create QR from the path param
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

# Confirmed page
@app.route('/confirmed/<int:order_id>')
@login_required
def confirmed(order_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, session['user']['id']))
    order = cur.fetchone()
    cur.close(); conn.close()
    if not order:
        flash('Pedido não encontrado.', 'danger')
        return redirect(url_for('index'))
    return render_template('confirmed.html', order=order)

# Order history (user)
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
    cur.close(); conn.close()
    return render_template('history.html', title='Histórico de Compras', orders=orders)

# Pix payment page (shows QR and confirm button)
@app.route('/pix_payment/<int:order_id>')
@login_required
def pix_payment(order_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, session['user']['id']))
    order = cur.fetchone()
    cur.close(); conn.close()
    if not order:
        flash('Pedido não encontrado.', 'danger')
        return redirect(url_for('index'))

    pix_data = f"pix://pagamento?valor={order['total']:.2f}&pedido={order_id}"

    # generate qrcode bytes and base64
    qr = qrcode.make(pix_data)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('pix_payment.html', order=order, qr_b64=qr_b64)

# confirm pix route (POST from pix_payment page)
@app.route('/confirm_pix/<int:order_id>', methods=['POST'])
@login_required
def confirm_pix(order_id):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE id=%s AND user_id=%s", (order_id, user['id']))
    order = cur.fetchone()
    if not order:
        cur.close(); conn.close()
        flash("Pedido não encontrado.", "danger")
        return redirect(url_for('index'))

    cur2 = conn.cursor()
    cur2.execute("UPDATE orders SET status='concluido' WHERE id=%s", (order_id,))
    conn.commit()
    cur2.close(); cur.close(); conn.close()

    flash("Pagamento confirmado com sucesso!", "success")
    return redirect(url_for('confirmed', order_id=order_id))

# user order list
@app.route('/orders')
@login_required
def orders():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM orders WHERE user_id = %s ORDER BY created_at DESC", (session['user']['id'],))
    orders = cur.fetchall()
    cur.close(); conn.close()
    return render_template('orders.html', orders=orders)

# ✅ Atualizar todos os produtos de uma vez
@app.route('/admin/products/update_all', methods=['POST'])
@admin_required
def admin_update_all_products():
    conn = get_db()
    cur = conn.cursor()

    try:
        # Percorrer todos os produtos enviados no formulário
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

            # Atualizar no banco
            cur.execute("""
                UPDATE products
                SET name=%s, description=%s, price=%s, stock=%s, category=%s,
                    image_url=COALESCE(%s, image_url)
                WHERE id=%s
            """, (name, description, price, stock, category, image_url, pid))

        conn.commit()
        flash("Produtos atualizados com sucesso!", "success")

    except Exception as e:
        conn.rollback()
        print("Erro:", e)
        flash("Erro ao atualizar produtos.", "error")

    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_products'))

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
    cur.close(); conn.close()
    return render_template("admin_orders.html", orders=orders)


# Página do chat
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
    cur.close(); conn.close()
    return render_template('chat.html', messages=messages)

# Enviar mensagem
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
    cur.close(); conn.close()
    return redirect(url_for('chat'))

@app.route('/categoria/<string:name>')
def category(name):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products WHERE category = %s ORDER BY created_at DESC", (name,))
    products = cur.fetchall()
    cur.close(); conn.close()
    return render_template('category.html', products=products, category_name=name)


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

        if new_pw != confirm_pw:
            flash('A nova senha e a confirmação não coincidem.', 'danger')
            return redirect(url_for('change_password'))

        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT password_hash FROM users WHERE id = %s", (session['user']['id'],))
        user = cur.fetchone()

        if not user or not check_password_hash(user['password_hash'], current):
            flash('Senha atual incorreta.', 'danger')
            cur.close(); conn.close()
            return redirect(url_for('change_password'))

        hashed = generate_password_hash(new_pw)
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed, session['user']['id']))
        conn.commit()
        cur.close(); conn.close()

        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True)


@app.route("/admin")
@login_required  # se quiser restringir
def admin_panel():
    return render_template("admin.html", title="Painel Administrativo")
