from flask import Flask, render_template, request, redirect, session, url_for
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = 'segredo123'  # Use uma chave segura no projeto real
bcrypt = Bcrypt(app)

# Função para conectar com o banco
def conectar_db():
    return sqlite3.connect('usuarios.db')

# Criar a tabela de usuários se não existir
def criar_tabela():
    conn = conectar_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

criar_tabela()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['senha']
        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

        try:
            conn = conectar_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO usuarios (username, senha) VALUES (?, ?)', (username, senha_hash))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Usuário já existe!"
        
    return render_template('cadastro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['senha']

        conn = conectar_db()
        cursor = conn.cursor()
        cursor.execute('SELECT senha FROM usuarios WHERE username = ?', (username,))
        resultado = cursor.fetchone()
        conn.close()

        if resultado and bcrypt.check_password_hash(resultado[0], senha):
            session['usuario'] = username
            return redirect(url_for('painel'))
        else:
            return "Login inválido!"

    return render_template('login.html')

@app.route('/painel')
def painel():
    if 'usuario' in session:
        return render_template('painel.html', usuario=session['usuario'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
