# ==============================================
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from fpdf import FPDF
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import fdb
import jwt
import re
import os
import logging
import datetime
# ----------------------------------------------
#  CONFIGURAÇÕES GERAIS DO APLICATIVO
# ----------------------------------------------
app = Flask(__name__)  # Cria a aplicação Flask
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  # Chave secreta para geração de tokens JWT
CORS(app, resources={r"/*": {"origins": "*"}})  # Permite CORS (origem cruzada) em todas as rotas

UPLOAD_FOLDER = 'static/imagens'  # Pasta padrão para upload de imagens
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Extensões permitidas para upload
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # Configuração do Flask para pasta de upload
# ----------------------------------------------
#  FUNÇÕES AUXILIARES
# ----------------------------------------------
def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida ex: jpg, pdf etc."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    # Retorna True se a extensão do arquivo estiver na lista permitida
def get_db_connection():
    """Cria e retorna a conexão com o banco Firebird."""
    return fdb.connect(
        dsn=r'localhost:C:\Users\Aluno\Desktop\AUTOPRIME.FDB',  # DSN com caminho do banco
        user='SYSDBA',  # Usuário do banco
        password='sysdba',  # Senha do banco
        charset='UTF8'  # Define charset UTF-8 para a conexão
    )
def validar_senha(senha):
    """Valida se a senha atende aos requisitos mínimos."""
    # Senha deve ter pelo menos 8 caracteres, uma letra maiúscula, um número e um símbolo
    return (
        len(senha) >= 8
        and re.search(r'[A-Z]', senha)
        and re.search(r'[0-9]', senha)
        and re.search(r'[\W_]', senha)
    )
def generate_token(user_id, email):
    """Gera token JWT com validade de 1 hora."""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Expira em 1 hora
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')  # Gera token JWT
    # Retorna token no formato string (pyjwt retorna bytes em algumas versões)
    return token.decode('utf-8') if isinstance(token, bytes) else token
def dict_from_row(cursor, row):
    """Converte uma linha SQL em dicionário."""
    columns = [col[0].lower() for col in cursor.description]  # Obtém nomes das colunas
    return dict(zip(columns, row))  # Junta nomes das colunas com valores da linha
# ----------------------------------------------
# 🖼 ROTA PARA SERVIR IMAGENS
# ----------------------------------------------
@app.route('/static/imagens/<filename>')
def imagens(filename):
    """
     GET /static/imagens/<filename>
    Serve imagens armazenadas na pasta /static/imagens.
    Parâmetro:
        - filename: nome do arquivo.
    Retorna:
        - A imagem requisitada.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    # Retorna arquivo da pasta configurada para download ou visualização no navegador
# ============================================================
#  ROTAS DE USUÁRIOS
# ============================================================
@app.route('/cadastro', methods=['GET'])
def lista_usuario():
    """
    👥 GET /cadastro
    Retorna todos os usuários cadastrados no sistema.
    Retorna:
        - Lista JSON com id, nome, email, cargo e status ativo.
    """
    con = get_db_connection()  # Abre conexão com o banco
    cur = con.cursor()
    cur.execute("SELECT ID_CADASTRO, NOME, EMAIL, CARGO, ATIVO FROM CADASTRO")  # Busca usuários
    usuarios = [dict_from_row(cur, u) for u in cur.fetchall()]  # Converte resultado em lista de dicionários
    cur.close()
    con.close()
    return jsonify({'mensagem': 'Lista de usuários', 'cadastro': usuarios})  # Retorna JSON com usuários
@app.route('/cadastro', methods=['POST'])
def criar_usuario():
    """
    📝 POST /cadastro
    Cadastra um novo usuário.
    JSON esperado:
        {
            "nome": "Fulano",
            "email": "fulano@email.com",
            "cargo": "Administrador",
            "senha": "Senha@123"
        }
    Retorna:
        - Mensagem de sucesso ou erro.
    """
    data = request.get_json()  # Recebe dados JSON do cliente
    nome, email, cargo, senha = data.get('nome'), data.get('email'), data.get('cargo'), data.get('senha')

    if not validar_senha(senha):  # Valida senha com a função auxiliar
        return jsonify({"error": "Senha fraca: mínimo 8 caracteres, 1 maiúscula, 1 número e 1 símbolo."}), 400

    con = get_db_connection()
    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM CADASTRO WHERE EMAIL = ?", (email,))  # Verifica se email já existe
    if cursor.fetchone():
        cursor.close()
        con.close()
        return jsonify({"error": "Usuário já cadastrado"}), 400

    senha_hash = generate_password_hash(senha, method='pbkdf2:sha256')  # Cria hash da senha para segurança
    cursor.execute("""
        INSERT INTO CADASTRO (NOME, EMAIL, CARGO, SENHA, ATIVO)
        VALUES (?, ?, ?, ?, ?)
    """, (nome, email, cargo, senha_hash, 1))  # Insere novo usuário com status ativo=1
    con.commit()
    cursor.close()
    con.close()
    return jsonify({'mensagem': 'Usuário cadastrado com sucesso!'}), 201  # Resposta de criação ok
@app.route('/edit_cadastro', methods=['PUT'])
def editar_usuario():
    """
    ✏️ PUT /edit_cadastro
    Atualiza dados de um usuário existente.
    JSON esperado:
        {
            "id_cadastro": 1,
            "nome": "Novo Nome",
            "email": "novo@email.com",
            "ativo": 1
        }
    Retorna:
        - Mensagem de sucesso ou erro.
    """
    data = request.get_json()
    id_cadastro = data.get('id_cadastro')  # ID obrigatório para atualizar

    if not id_cadastro:
        return jsonify({"error": "ID obrigatório"}), 400

    con = get_db_connection()
    cursor = con.cursor()
    cursor.execute("SELECT ID_CADASTRO FROM CADASTRO WHERE ID_CADASTRO = ?", (id_cadastro,))  # Verifica se usuário existe
    if not cursor.fetchone():
        cursor.close()
        con.close()
        return jsonify({"error": "Usuário não encontrado"}), 404

    campos, valores = [], []
    # Percorre campos que podem ser atualizados e prepara a query
    for campo in ["nome", "email", "cargo", "senha", "ativo"]:
        valor = data.get(campo)
        if valor is not None:
            if campo == "senha":
                if not validar_senha(valor):
                    return jsonify({"error": "Senha inválida"}), 400
                valor = generate_password_hash(valor, method='pbkdf2:sha256')  # Atualiza senha com hash
            campos.append(f"{campo.upper()} = ?")
            valores.append(valor)

    if not campos:
        return jsonify({"error": "Nenhum campo para atualizar"}), 400

    valores.append(id_cadastro)  # Valor do WHERE da query
    sql = f"UPDATE CADASTRO SET {', '.join(campos)} WHERE ID_CADASTRO = ?"
    cursor.execute(sql, tuple(valores))  # Executa atualização no banco
    con.commit()
    cursor.close()
    con.close()
    return jsonify({"mensagem": "Cadastro atualizado com sucesso!"}), 200
@app.route('/login', methods=['POST'])
def login():
    """
     POST /login
    Realiza login e gera token JWT.
    JSON esperado:
        {
            "email": "fulano@email.com",
            "senha": "Senha@123"
        }
    Retorna:
        - Dados do usuário e token JWT.
    """
    try:
        data = request.get_json(force=True)
        email, senha = data.get('email'), data.get('senha')

        con = get_db_connection()
        cursor = con.cursor()
        cursor.execute("""
            SELECT ID_CADASTRO, NOME, EMAIL, CARGO, ATIVO, SENHA, TENTATIVAS_LOGIN
            FROM CADASTRO WHERE EMAIL = ?
        """, (email,))
        row = cursor.fetchone()

        if not row:
            return jsonify({"error": "Email não encontrado"}), 404

        usuario = dict_from_row(cursor, row)

        if int(usuario['ativo']) == 0:
            return jsonify({"error": "Conta inativa"}), 403

        if check_password_hash(usuario['senha'], senha):  # Verifica senha
            cursor.execute("UPDATE CADASTRO SET TENTATIVAS_LOGIN = 0 WHERE ID_CADASTRO = ?", (usuario['id_cadastro'],))
            con.commit()
            token = generate_token(usuario['id_cadastro'], email)  # Gera token JWT
            return jsonify({
                "mensagem": "Login realizado com sucesso!",
                "id_cadastro": usuario['id_cadastro'],
                "nome": usuario['nome'],
                "cargo": usuario['cargo'],
                "token": token
            }), 200
        else:
            # Incrementa tentativas de login e bloqueia após 3
            novas_tentativas = (usuario.get('tentativas_login') or 0) + 1
            if novas_tentativas >= 3:
                cursor.execute("UPDATE CADASTRO SET TENTATIVAS_LOGIN = ?, ATIVO = 0 WHERE ID_CADASTRO = ?",
                               (novas_tentativas, usuario['id_cadastro']))
                con.commit()
                return jsonify({"error": "Conta bloqueada após 3 tentativas"}), 403
            else:
                cursor.execute("UPDATE CADASTRO SET TENTATIVAS_LOGIN = ? WHERE ID_CADASTRO = ?",
                               (novas_tentativas, usuario['id_cadastro']))
                con.commit()
                return jsonify({"error": f"Senha incorreta. {3 - novas_tentativas} tentativa(s) restante(s)."}), 401

    except Exception as e:
        logging.error(f"Erro no login: {str(e)}")  # Log de erros no servidor
        return jsonify({"error": "Erro interno no servidor"}), 500

    finally:
        if cursor: cursor.close()
        if con: con.close()
# ============================================================
# 🛍 ROTAS DE PRODUTOS (CRUD COMPLETO)
# ============================================================
@app.route('/produtos', methods=['GET'])
def lista_produtos():
    """
     GET /produtos
    Retorna todos os produtos cadastrados.
    Retorna:
        - Lista de produtos (JSON)
    """
    con = get_db_connection()
    cursor = con.cursor()
    cursor.execute("SELECT ID, NOME, DESCRICAO, MARCA, PRECO, ACABAMENTO, IMAGEM, ID_VENDEDOR FROM PRODUTOS")
    produtos = [dict_from_row(cursor, p) for p in cursor.fetchall()]  # Transforma resultados em lista de dicionários
    cursor.close()
    con.close()
    return jsonify({'mensagem': 'Lista de produtos', 'produtos': produtos})
@app.route('/produto/<int:id>', methods=['GET'])
def buscar_produto_id(id):
    """
    🔍 GET /produto/<id>
    Busca um produto pelo ID.
    Retorna:
        - Dados do produto ou erro se não encontrado.
    """
    con = get_db_connection()
    cursor = con.cursor()
    cursor.execute("SELECT ID, NOME, DESCRICAO, PRECO, MARCA, IMAGEM FROM PRODUTOS WHERE ID = ?", (id,))
    row = cursor.fetchone()
    cursor.close()
    con.close()

    if not row:
        return jsonify({'erro': 'Produto não encontrado'}), 404

    return jsonify({'mensagem': 'Produto encontrado', 'produto': dict_from_row(cursor, row)}), 200
@app.route('/produto', methods=['POST'])
def criar_produto():
    """
    POST /produto
    Cadastra um novo produto.
    Form-data esperado:
        - nome, descricao, preco, acabamento, marca, id_vendedor, imagem
    Retorna:
        - ID do produto e mensagem de sucesso.
    """
    nome = request.form.get('nome')
    descricao = request.form.get('descricao')
    preco = request.form.get('preco')
    acabamento = request.form.get('acabamento')
    marca = request.form.get('marca')
    id_vendedor = request.form.get('id_vendedor')
    file = request.files.get('imagem')

    # 🚨 Validação dos campos obrigatórios
    if not nome:
        return jsonify({"erro": "O campo 'nome' é obrigatório."}), 400
    if not preco:
        return jsonify({"erro": "O campo 'preco' é obrigatório."}), 400
    if not id_vendedor:
        return jsonify({"erro": "O campo 'id_vendedor' é obrigatório."}), 400

    imagem = None
    con = get_db_connection()
    cursor = con.cursor()

    # Verifica se produto já existe
    cursor.execute("SELECT 1 FROM PRODUTOS WHERE NOME = ?", (nome,))
    if cursor.fetchone():
        cursor.close()
        con.close()
        return jsonify({"erro": "Produto já cadastrado."}), 400

    # Insere o produto
    cursor.execute("""
        INSERT INTO PRODUTOS (NOME, DESCRICAO, PRECO, ACABAMENTO, MARCA, ID_VENDEDOR)
        VALUES (?, ?, ?, ?, ?, ?) RETURNING ID
    """, (nome, descricao, preco, acabamento, marca, id_vendedor))
    produto_id = cursor.fetchone()[0]

    # Salva imagem (se houver)
    if file and allowed_file(file.filename):
        extensao = os.path.splitext(file.filename)[1]
        nome_imagem = f"{produto_id}{extensao}"
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "produto")
        os.makedirs(pasta_destino, exist_ok=True)
        caminho = os.path.join(pasta_destino, nome_imagem).replace("\\", "/")
        file.save(caminho)
        imagem = f"produto/{nome_imagem}"
        cursor.execute("UPDATE PRODUTOS SET IMAGEM = ? WHERE ID = ?", (imagem, produto_id))

    con.commit()
    cursor.close()
    con.close()

    return jsonify({'mensagem': 'Produto cadastrado com sucesso!', 'produto_id': produto_id}), 201
@app.route('/produto/edit/<int:id>', methods=['PUT'])
def editar_produto(id):
    """
    Atualiza informações de um produto existente.
    """
    try:
        data = request.form
        id_produto = id  # O ID é obtido da URL

        if not id_produto:
            return jsonify({"error": "ID obrigatório"}), 400

        con = get_db_connection()
        cursor = con.cursor()

        cursor.execute("SELECT ID FROM PRODUTOS WHERE ID = ?", (id_produto,))  # Verifica existência do produto
        if not cursor.fetchone():
            cursor.close()
            con.close()
            return jsonify({"error": "Produto não encontrado"}), 404

        campos, valores = [], []
        # Campos passíveis de atualização via form-data
        for campo in ["nome", "descricao", "preco", "acabamento", "marca"]:
            valor = data.get(campo)
            if valor:
                campos.append(f"{campo.upper()} = ?")
                valores.append(valor)

        file = request.files.get('imagem')
        if file and allowed_file(file.filename):  # Se nova imagem enviada e válida, salva e atualiza campo
            extensao = os.path.splitext(file.filename)[1]
            nome_imagem = f"{id_produto}{extensao}"
            pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "produto")
            os.makedirs(pasta_destino, exist_ok=True)
            caminho = os.path.join(pasta_destino, nome_imagem).replace("\\", "/")
            file.save(caminho)
            imagem = f"produto/{nome_imagem}"
            campos.append("IMAGEM = ?")
            valores.append(imagem)

        if not campos:
            return jsonify({"error": "Nenhum campo para atualizar"}), 400

        valores.append(id_produto)
        sql = f"UPDATE PRODUTOS SET {', '.join(campos)} WHERE ID = ?"
        cursor.execute(sql, tuple(valores))  # Atualiza o produto no banco
        con.commit()

        cursor.close()
        con.close()
        return jsonify({"mensagem": "Produto atualizado com sucesso!"}), 200

    except Exception as e:
        logging.error(f"Erro ao atualizar produto: {str(e)}")
        return jsonify({"error": "Erro interno no servidor"}), 500
@app.route('/produto/imagem/edit/<int:id>', methods=['PUT'])
def editar_imagem_produto(id):
    """
    ✏️ PUT /produto/imagem/edit/<id>
    Atualiza a imagem de um produto existente.
    Form-data esperado:
        - imagem (arquivo de imagem)
    Retorna:
        - Mensagem de sucesso ou erro.
    """
    file = request.files.get('imagem')
    if not file or not allowed_file(file.filename):  # Verifica se envio da imagem é válido
        return jsonify({"error": "Imagem inválida ou não enviada."}), 400

    con = get_db_connection()
    cursor = con.cursor()

    cursor.execute("SELECT ID FROM PRODUTOS WHERE ID = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        con.close()
        return jsonify({"error": "Produto não encontrado"}), 404

    extensao = os.path.splitext(file.filename)[1]  # Pega extensão original
    nome_imagem = f"{id}{extensao}"  # Nomeia arquivo imagem com ID do produto
    pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "produto")
    os.makedirs(pasta_destino, exist_ok=True)
    caminho = os.path.join(pasta_destino, nome_imagem).replace("\\", "/")
    file.save(caminho)  # Salva imagem no servidor

    imagem = f"produto/{nome_imagem}"  # Caminho relativo para banco
    cursor.execute("UPDATE PRODUTOS SET IMAGEM = ? WHERE ID = ?", (imagem, id))  # Atualiza registro do produto
    con.commit()

    cursor.close()
    con.close()

    return jsonify({"mensagem": "Imagem do produto atualizada com sucesso!"}), 200
@app.route('/produto/<int:id>', methods=['DELETE'])
def remover_produto(id):
    """
    🗑️ DELETE /produto/<id>
    Remove um produto pelo ID.
    Retorna:
        - Mensagem de sucesso ou erro.
    """
    con = get_db_connection()
    cursor = con.cursor()
    cursor.execute("SELECT ID FROM PRODUTOS WHERE ID = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        con.close()
        return jsonify({"error": "Produto não encontrado"}), 404

    cursor.execute("DELETE FROM PRODUTOS WHERE ID = ?", (id,))
    con.commit()
    cursor.close()
    con.close()
    return jsonify({"mensagem": "Produto removido com sucesso!"}), 200
# ============================================================
# 💸 ROTAS DE VENDAS E CASHBACK
# ============================================================
@app.route('/vendas', methods=['GET'])
def listar_vendas():
    """
    📈 GET /vendas
    Lista todas as vendas registradas.

    Retorna:
    - ID da venda
    - ID do produto
    - ID do cliente
    - ID do vendedor
    - Quantidade de produtos
    - Valor total da venda
    - Data da venda
    """
    con = get_db_connection()  # Conecta ao banco de dados
    cursor = con.cursor()

    cursor.execute("""
        SELECT ID_VENDA, ID_PRODUTO, ID_CLIENTE, ID_VENDEDOR, QUANTIDADE, VALOR_TOTAL, DATA_VENDA
        FROM VENDAS
        ORDER BY ID_VENDA DESC 
    """)

    # Ordena pelas vendas mais recentes

    vendas = cursor.fetchall()  # Pega todas as vendas no banco

    cursor.close()  # Fecha o cursor
    con.close()  # Fecha a conexão com o banco

    # Monta a resposta com os dados de cada venda
    resultado = []
    for v in vendas:
        resultado.append({
            "id_venda": v[0],
            "id_produto": v[1],
            "id_cliente": v[2],
            "id_vendedor": v[3],
            "quantidade": v[4],
            "valor_total": float(v[5]),
            "data_venda": str(v[6])  # Formata a data para string
        })

    return jsonify(resultado)  # Retorna a lista de vendas em formato JSON
@app.route('/venda', methods=['POST'])
def registrar_venda():
    """
    💵 POST /venda
    Registra uma venda e gera automaticamente o cashback (5%).

    JSON esperado:
    {
        "email_cliente": "cliente@teste.com",   # E-mail do cliente
        "id_produto": 1,                        # ID do produto a ser vendido
        "quantidade": 2,                        # Quantidade do produto
        "valor_unitario": 50.00                 # Preço unitário do produto
    }
    """
    data = request.get_json()

    # Extrai os dados enviados
    email_cliente = data.get('email_cliente')
    id_produto = data.get('id_produto')
    quantidade = int(data.get('quantidade', 1))
    valor_unitario = float(data.get('valor_unitario', 0))

    # 🟢 Define o vendedor automaticamente (sem pedir no HTML)
    email_vendedor = 'vendedor@gmail.com'

    # Verifica se os campos obrigatórios foram fornecidos
    if not data or not all([email_cliente, id_produto, valor_unitario]):
        return jsonify({
            "erro": "Campos obrigatórios ausentes",
            "json_recebido": data
        }), 400

    con = get_db_connection()
    cursor = con.cursor()

    try:
        # 🔹 Busca cliente no banco
        cursor.execute("SELECT ID_CADASTRO, CARGO FROM CADASTRO WHERE EMAIL = ?", (email_cliente,))
        row_cliente = cursor.fetchone()
        if not row_cliente:
            return jsonify({"erro": "Cliente não encontrado"}), 404
        if row_cliente[1].strip().lower() != "cliente":
            return jsonify({"erro": f"O e-mail '{email_cliente}' não pertence a um CLIENTE"}), 400
        id_cliente = row_cliente[0]

        # 🔹 Busca vendedor padrão no banco
        cursor.execute("SELECT ID_CADASTRO, CARGO FROM CADASTRO WHERE EMAIL = ?", (email_vendedor,))
        row_vendedor = cursor.fetchone()
        if not row_vendedor:
            return jsonify({"erro": "Vendedor padrão não encontrado no banco"}), 404
        if row_vendedor[1].strip().lower() != "vendedor":
            return jsonify({"erro": f"O e-mail '{email_vendedor}' não pertence a um VENDEDOR"}), 400
        id_vendedor = row_vendedor[0]

        # 🔹 Calcula valores
        valor_total = round(valor_unitario * quantidade, 2)
        valor_cashback = round(valor_total * 0.05, 2)

        # 🔹 Registra a venda
        cursor.execute("""
            INSERT INTO VENDAS (ID_PRODUTO, ID_CLIENTE, ID_VENDEDOR, QUANTIDADE, VALOR_TOTAL)
            VALUES (?, ?, ?, ?, ?)
            RETURNING ID_VENDA
        """, (id_produto, id_cliente, id_vendedor, quantidade, valor_total))
        id_venda = cursor.fetchone()[0]

        # 🔹 Registra o cashback
        cursor.execute("""
            INSERT INTO CASHBACKS (ID_CLIENTE, ID_VENDA, VALOR_CASHBACK)
            VALUES (?, ?, ?)
            RETURNING ID_CASHBACK
        """, (id_cliente, id_venda, valor_cashback))
        id_cashback = cursor.fetchone()[0]

        con.commit()
        return jsonify({
            "mensagem": "Venda registrada com sucesso!",
            "id_venda": id_venda,
            "valor_total": valor_total,
            "cashback": {
                "id_cashback": id_cashback,
                "valor_cashback": valor_cashback
            }
        }), 201

    except Exception as e:
        con.rollback()
        return jsonify({"erro": str(e)}), 500

    finally:
        cursor.close()
        con.close()
@app.route('/cashbacks', methods=['GET'])
def listar_cashbacks():
    """
    📈 GET /cashbacks
    Lista todos os cashbacks gerados.

    Retorna:
    - ID do cashback
    - ID do cliente
    - ID da venda
    - Valor do cashback
    - Data de geração do cashback
    """
    con = get_db_connection()  # Conecta ao banco de dados
    cursor = con.cursor()

    # Query corrigida: comentário fora da query SQL
    cursor.execute("""
        SELECT ID_CASHBACK, ID_CLIENTE, ID_VENDA, VALOR_CASHBACK, DATA_GERACAO
        FROM CASHBACKS
        ORDER BY ID_CASHBACK DESC
    """)
    # Ordena pelos cashbacks mais recentes

    linhas = cursor.fetchall()  # Pega todos os cashbacks registrados

    cursor.close()  # Fecha o cursor
    con.close()  # Fecha a conexão com o banco

    # Monta a resposta com os dados de cada cashback
    resultado = []
    for c in linhas:
        resultado.append({
            "id_cashback": c[0],
            "id_cliente": c[1],
            "id_venda": c[2],
            "valor_cashback": float(c[3]),
            "data_geracao": str(c[4])  # Formata a data de geração do cashback
        })

    return jsonify(resultado)  # Retorna a lista de cashbacks em formato JSON
@app.route('/carrinho/adicionar', methods=['POST'])
def adicionar_ao_carrinho():
    """
    🛍️ POST /carrinho/adicionar
    Adiciona um produto ao carrinho de um cliente.

    JSON esperado:
    {
        "email_cliente": "cliente@teste.com",   # Email do cliente
        "id_produto": 1,                         # ID do produto a ser adicionado
        "quantidade": 2                          # Quantidade do produto a ser adicionada
    }
    """
    data = request.get_json()  # Recebe os dados enviados no corpo da requisição (em formato JSON)
    email_cliente = data.get('email_cliente')
    id_produto = data.get('id_produto')
    quantidade = int(data.get('quantidade', 1))  # Pega a quantidade ou usa 1 como padrão

    # Valida se todos os campos obrigatórios estão presentes
    if not all([email_cliente, id_produto, quantidade]):
        return jsonify({"erro": "Campos obrigatórios ausentes"}), 400  # Retorna erro caso falte algum campo

    con = get_db_connection()  # Conecta ao banco de dados
    cursor = con.cursor()

    try:
        # Verifica se o cliente existe no banco de dados pelo e-mail
        cursor.execute("SELECT ID_CADASTRO, CARGO FROM CADASTRO WHERE EMAIL = ?", (email_cliente,))
        row_cliente = cursor.fetchone()
        if not row_cliente:
            return jsonify({"erro": "Cliente não encontrado"}), 404  # Cliente não encontrado no banco
        if row_cliente[1].strip().lower() != "cliente":
            return jsonify({"erro": "Somente clientes podem ter carrinho"}), 400  # Verifica se é um cliente

        id_cliente = row_cliente[0]  # ID do cliente

        # Busca o produto no banco de dados pelo ID
        cursor.execute("SELECT PRECO FROM PRODUTOS WHERE ID = ?", (id_produto,))
        row_produto = cursor.fetchone()
        if not row_produto:
            return jsonify({"erro": "Produto não encontrado"}), 404  # Produto não encontrado no banco
        preco_unitario = float(row_produto[0])  # Preço unitário do produto

        # Calcula o valor total do produto no carrinho (preço unitário * quantidade)
        valor_total = round(preco_unitario * quantidade, 2)

        # Verifica se o produto já está no carrinho do cliente
        cursor.execute("""
            SELECT ID_ITEM, QUANTIDADE, VALOR_TOTAL
            FROM CARRINHO
            WHERE ID_CLIENTE = ? AND ID_PRODUTO = ?
        """, (id_cliente, id_produto))
        existente = cursor.fetchone()

        if existente:
            # Se o produto já estiver no carrinho, atualiza a quantidade e o valor total
            nova_qtd = existente[1] + quantidade
            novo_total = round(preco_unitario * nova_qtd, 2)
            cursor.execute("""
                UPDATE CARRINHO SET QUANTIDADE = ?, VALOR_TOTAL = ?
                WHERE ID_ITEM = ?
            """, (nova_qtd, novo_total, existente[0]))  # Atualiza o item no banco
        else:
            # Caso contrário, insere o novo item no carrinho
            cursor.execute("""
                INSERT INTO CARRINHO (ID_CLIENTE, ID_PRODUTO, QUANTIDADE, VALOR_UNITARIO, VALOR_TOTAL)
                VALUES (?, ?, ?, ?, ?)
            """, (id_cliente, id_produto, quantidade, preco_unitario, valor_total))  # Insere no banco

        con.commit()  # Confirma a transação no banco
        return jsonify({"mensagem": "Produto adicionado ao carrinho com sucesso!"}), 201  # Retorna sucesso

    except Exception as e:
        con.rollback()  # Caso ocorra erro, faz rollback da transação
        return jsonify({"erro": str(e)}), 500  # Retorna o erro ocorrido
    finally:
        cursor.close()  # Fecha o cursor do banco
        con.close()  # Fecha a conexão com o banco
@app.route('/carrinho/<email_cliente>', methods=['GET'])
def listar_carrinho(email_cliente):
    """
    📦 GET /carrinho/<email_cliente>
    Lista todos os produtos no carrinho de um cliente.

    Parâmetros:
    - email_cliente: e-mail do cliente para o qual o carrinho será listado.
    """
    con = get_db_connection()  # Conecta ao banco de dados
    cursor = con.cursor()

    try:
        # Verifica se o cliente existe no banco de dados
        cursor.execute("SELECT ID_CADASTRO FROM CADASTRO WHERE EMAIL = ?", (email_cliente,))
        row_cliente = cursor.fetchone()
        if not row_cliente:
            return jsonify({"erro": "Cliente não encontrado"}), 404  # Cliente não encontrado no banco
        id_cliente = row_cliente[0]

        # Busca todos os itens no carrinho do cliente
        cursor.execute("""
            SELECT C.ID_ITEM, P.NOME, P.MARCA, C.QUANTIDADE, C.VALOR_UNITARIO, C.VALOR_TOTAL, C.DATA_ADICAO
            FROM CARRINHO C
            JOIN PRODUTOS P ON C.ID_PRODUTO = P.ID
            WHERE C.ID_CLIENTE = ?
            ORDER BY C.DATA_ADICAO DESC
        """, (id_cliente,))

        itens = cursor.fetchall()  # Pega todos os itens do carrinho
        resultado = []
        for i in itens:
            # Monta a resposta em formato JSON para os itens do carrinho
            resultado.append({
                "id_item": i[0],
                "nome_produto": i[1],
                "marca": i[2],
                "quantidade": i[3],
                "valor_unitario": float(i[4]),
                "valor_total": float(i[5]),
                "data_adicao": str(i[6])  # Formata a data de adição para string
            })

        return jsonify({
            "cliente": email_cliente,
            "total_itens": len(resultado),  # Retorna a quantidade total de itens
            "carrinho": resultado  # Retorna os itens no carrinho
        })

    except Exception as e:
        return jsonify({"erro": str(e)}), 500  # Retorna erro caso aconteça algum problema
    finally:
        cursor.close()  # Fecha o cursor do banco
        con.close()  # Fecha a conexão com o banco
@app.route('/carrinho/remover/<int:id_item>', methods=['DELETE'])
def remover_item_carrinho(id_item):
    """
    🗑 DELETE /carrinho/remover/<id_item>
    Remove um item do carrinho.

    Parâmetro:
    - id_item: ID do item a ser removido do carrinho.
    """
    con = get_db_connection()  # Conecta ao banco de dados
    cursor = con.cursor()

    try:
        # Verifica se o item existe no carrinho
        cursor.execute("SELECT ID_ITEM FROM CARRINHO WHERE ID_ITEM = ?", (id_item,))
        if not cursor.fetchone():
            return jsonify({"erro": "Item não encontrado"}), 404  # Retorna erro caso o item não exista

        # Deleta o item do carrinho
        cursor.execute("DELETE FROM CARRINHO WHERE ID_ITEM = ?", (id_item,))
        con.commit()  # Confirma a exclusão no banco
        return jsonify({"mensagem": "Item removido do carrinho com sucesso!"}), 200  # Retorna sucesso

    except Exception as e:
        con.rollback()  # Caso ocorra erro, faz rollback da transação
        return jsonify({"erro": str(e)}), 500  # Retorna erro caso algo dê errado
    finally:
        cursor.close()  # Fecha o cursor do banco
        con.close()  # Fecha a conexão com o banco
# ---------- CLIENTES ----------
@app.route('/pdf/clientes', methods=['GET'])
def pdf_clientes():
    try:
        # Conecta no banco de dados
        con = get_db_connection()
        cur = con.cursor()
        # Executa a consulta para buscar clientes ativos ou inativos ordenados por nome
        cur.execute("""
            SELECT ID_CADASTRO, NOME, EMAIL, ATIVO
            FROM CADASTRO
            WHERE UPPER(CARGO) = 'CLIENTE'
            ORDER BY NOME
        """)
        usuarios = cur.fetchall()  # Busca todos os resultados da consulta
        cur.close()  # Fecha cursor
        con.close()  # Fecha conexão

        pdf = FPDF()  # Cria objeto PDF
        pdf.add_page()  # Adiciona uma página

        # Define fonte para o título e escreve o título centralizado
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 10, "Relatório de Clientes", ln=True, align="C")
        pdf.ln(8)  # Adiciona espaço vertical

        # Cabeçalho da tabela com fundo escuro e texto branco
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(40, 40, 40)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(70, 70, 70)
        pdf.cell(20, 10, "ID", 1, 0, "C", True)
        pdf.cell(60, 10, "NOME", 1, 0, "C", True)
        pdf.cell(70, 10, "EMAIL", 1, 0, "C", True)
        pdf.cell(30, 10, "STATUS", 1, 1, "C", True)

        # Corpo da tabela com dados dos usuários
        pdf.set_font("Helvetica", "B", 11)
        fill = False  # Controle para alternar cor de fundo das linhas
        for u in usuarios:
            # Alterna cor de fundo entre azul claro e branco
            pdf.set_fill_color(197, 220, 255) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.set_draw_color(60, 60, 60)  # Cor da borda da célula
            pdf.set_text_color(0, 0, 0)  # Cor do texto padrão (preto)
            # Preenchimento das células com dados
            pdf.cell(20, 10, str(u[0]), 1, 0, "C", fill)  # ID
            pdf.cell(60, 10, str(u[1]), 1, 0, "L", fill)  # Nome
            pdf.cell(70, 10, str(u[2]), 1, 0, "L", fill)  # Email

            # Define a cor e texto do status de acordo com o campo ATIVO
            if u[3] == 1:
                pdf.set_text_color(0, 180, 0)  # Verde para ativo
                status = "ATIVO"
            else:
                pdf.set_text_color(200, 0, 0)  # Vermelho para inativo
                status = "INATIVO"
            pdf.cell(30, 10, status, 1, 1, "C", fill)  # Status da conta
            fill = not fill  # Alterna a cor da linha

        # Linha em branco e informações finais do relatório
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 12)
        # Total de registros no relatório
        pdf.cell(0, 10, f"Total de registros: {len(usuarios)}", ln=True)
        # Data e hora de geração do relatório
        pdf.cell(0, 10, f"Gerado em {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True)

        # Define o caminho para salvar o arquivo PDF
        caminho_pdf = os.path.join(os.getcwd(), "static", "relatorio_clientes.pdf")
        pdf.output(caminho_pdf)  # Salva o arquivo PDF no caminho definido

        # Envia o arquivo como anexo para download
        return send_file(caminho_pdf, as_attachment=True)

    except Exception as e:  # Em caso de erro, retorna um JSON com a mensagem
        return jsonify({"erro": str(e)}), 500
# ---------- VENDEDORES ----------
@app.route('/pdf/vendedores', methods=['GET'])
def pdf_vendedores():
    try:
        # Conecta ao banco de dados
        con = get_db_connection()
        cur = con.cursor()
        # Consulta os vendedores cadastrados
        cur.execute("""
            SELECT ID_CADASTRO, NOME, EMAIL, ATIVO
            FROM CADASTRO
            WHERE UPPER(CARGO) = 'VENDEDOR'
            ORDER BY NOME
        """)
        usuarios = cur.fetchall()
        cur.close()
        con.close()

        pdf = FPDF()
        pdf.add_page()

        # Título do relatório de vendedores
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 10, "Relatório de Vendedores", ln=True, align="C")
        pdf.ln(8)

        # Cabeçalho da tabela dos vendedores
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(40, 40, 40)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(70, 70, 70)
        pdf.cell(20, 10, "ID", 1, 0, "C", True)
        pdf.cell(60, 10, "NOME", 1, 0, "C", True)
        pdf.cell(70, 10, "EMAIL", 1, 0, "C", True)
        pdf.cell(30, 10, "STATUS", 1, 1, "C", True)

        # Dados dos vendedores na tabela
        pdf.set_font("Helvetica", "B", 11)
        fill = False
        for u in usuarios:
            # Alterna cores das linhas da tabela
            pdf.set_fill_color(197, 220, 255) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.set_draw_color(60, 60, 60)
            pdf.set_text_color(0, 0, 0)
            # Dados ID, Nome e Email
            pdf.cell(20, 10, str(u[0]), 1, 0, "C", fill)
            pdf.cell(60, 10, str(u[1]), 1, 0, "L", fill)
            pdf.cell(70, 10, str(u[2]), 1, 0, "L", fill)

            # Define status ativo/inativo com cores
            if u[3] == 1:
                pdf.set_text_color(0, 180, 0)
                status = "ATIVO"
            else:
                pdf.set_text_color(200, 0, 0)
                status = "INATIVO"
            pdf.cell(30, 10, status, 1, 1, "C", fill)
            fill = not fill

        # Dados finais e data de geração
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, f"Total de registros: {len(usuarios)}", ln=True)
        pdf.cell(0, 10, f"Gerado em {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True)

        # Salva e envia o PDF dos vendedores
        caminho_pdf = os.path.join(os.getcwd(), "static", "relatorio_vendedor.pdf")
        pdf.output(caminho_pdf)

        return send_file(caminho_pdf, as_attachment=True)

    except Exception as e:
        return jsonify({"erro": str(e)}), 500
# ---------- ADMINISTRADORES ----------
@app.route('/pdf/adms', methods=['GET'])
def pdf_adms():
    try:
        # Conexão com o banco para buscar administradores
        con = get_db_connection()
        cur = con.cursor()
        cur.execute("""
            SELECT ID_CADASTRO, NOME, EMAIL, ATIVO
            FROM CADASTRO
            WHERE UPPER(CARGO) = 'ADM'
            ORDER BY NOME
        """)
        usuarios = cur.fetchall()
        cur.close()
        con.close()

        pdf = FPDF()
        pdf.add_page()

        # Título do relatório de administradores
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 10, "Relatório de Administradores", ln=True, align="C")
        pdf.ln(8)

        # Cabeçalho da tabela dos administradores
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(40, 40, 40)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(70, 70, 70)
        pdf.cell(20, 10, "ID", 1, 0, "C", True)
        pdf.cell(60, 10, "NOME", 1, 0, "C", True)
        pdf.cell(70, 10, "EMAIL", 1, 0, "C", True)
        pdf.cell(30, 10, "STATUS", 1, 1, "C", True)

        # Linhas da tabela contendo dados
        pdf.set_font("Helvetica", "B", 11)
        fill = False
        for u in usuarios:
            pdf.set_fill_color(197, 220, 255) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.set_draw_color(60, 60, 60)
            pdf.set_text_color(0, 0, 0)
            # Detalhes ID, Nome e Email
            pdf.cell(20, 10, str(u[0]), 1, 0, "C", fill)
            pdf.cell(60, 10, str(u[1]), 1, 0, "L", fill)
            pdf.cell(70, 10, str(u[2]), 1, 0, "L", fill)

            # Status ativo ou inativo em cores distintas
            if u[3] == 1:
                pdf.set_text_color(0, 180, 0)
                status = "ATIVO"
            else:
                pdf.set_text_color(200, 0, 0)
                status = "INATIVO"
            pdf.cell(30, 10, status, 1, 1, "C", fill)
            fill = not fill

        # Informação do total de registros e data de geração do arquivo
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, f"Total de registros: {len(usuarios)}", ln=True)
        pdf.cell(0, 10, f"Gerado em {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True)

        # Caminho do arquivo PDF a ser salvo e enviado
        caminho_pdf = os.path.join(os.getcwd(), "static", "relatorio_adms.pdf")
        pdf.output(caminho_pdf)

        # Envia arquivo para download
        return send_file(caminho_pdf, as_attachment=True)

    except Exception as e:
        # Retorna erro em formato JSON caso tenha problema ao gerar relatório
        return jsonify({"erro": str(e)}), 500
# ============================================================
# 🚀 EXECUÇÃO DO SERVIDOR
# ============================================================
if __name__ == '__main__':
    # Inicia servidor Flask na porta 5000 e permite debug para desenvolvimento
    app.run(host='0.0.0.0', port=5000, debug=True)