import os
import json
import base64
import hashlib
import hmac
import secrets
import sqlite3
import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
from datetime import datetime, timedelta

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils


# ============================================================
# CONFIGURACIÓN GENERAL DE FALCONSIGNED
# ============================================================

APP_NAME = "FalconSigned"
PASSWORD_ITERATIONS = 300_000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

# Directorio donde se encuentra este archivo Python.
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "falconsigned.db"
CONFIG_PATH = BASE_DIR / "falconsigned_config.json"
KEYS_DIR = BASE_DIR / "keys"
KEYS_DIR.mkdir(exist_ok=True)
ENCRYPTED_DIR = BASE_DIR / "encryptados_documentos"
ENCRYPTED_DIR.mkdir(exist_ok=True)

# Variables globales de sesión.
archivo_seleccionado = ""
usuario_actual = None
vault_password_session = None


# ============================================================
# BASE DE DATOS
# ============================================================

def conectar_db():
    """
    QUÉ HACE:
        Abre una conexión con la base de datos SQLite de FalconSigned.

    CÓMO FUNCIONA:
        SQLite almacena toda la información estructurada en un archivo local
        llamado 'falconsigned.db'. Se usa sqlite3.Row para poder consultar las
        columnas por nombre, por ejemplo: fila["username"].
    """
    conexion = sqlite3.connect(DB_PATH)
    conexion.row_factory = sqlite3.Row
    return conexion


def inicializar_db():
    """
    QUÉ HACE:
        Crea las tablas necesarias si todavía no existen.

    CÓMO FUNCIONA:
        Se ejecutan sentencias CREATE TABLE IF NOT EXISTS para usuarios,
        claves criptográficas, documentos firmados y bitácora de auditoría.
        De esta forma, el programa puede iniciarse por primera vez sin que el
        usuario tenga que crear manualmente una base de datos.
    """
    with conectar_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_secret_enc TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                private_key_path TEXT NOT NULL,
                public_key_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )

    conn.execute(
    """
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        student_enc TEXT NOT NULL,
        carne_enc TEXT NOT NULL,
        document_type_enc TEXT NOT NULL,
        original_name TEXT NOT NULL,
        encrypted_path TEXT,
        nonce_b64 TEXT,
        encrypted_key_b64 TEXT,
        hash_hex TEXT NOT NULL,
        signature_b64 TEXT NOT NULL,
        key_id TEXT NOT NULL,
        signed_by TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY(key_id) REFERENCES keys(key_id)
    )
    """
)

    conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
            """
        )


def registrar_auditoria(username, action, details=""):
    """
    QUÉ HACE:
        Guarda una evidencia de las acciones importantes realizadas en el sistema.

    CÓMO FUNCIONA:
        Inserta en la tabla audit_logs el usuario, la acción, un detalle opcional
        y la fecha/hora. Esto permite demostrar quién firmó, verificó, revocó o
        administró claves y usuarios.
    """
    with conectar_db() as conn:
        conn.execute(
            "INSERT INTO audit_logs (username, action, details, created_at) VALUES (?, ?, ?, ?)",
            (username, action, details, datetime.now().isoformat(timespec="seconds")),
        )


# ============================================================
# CONTRASEÑAS Y AUTENTICACIÓN
# ============================================================

def validar_fortaleza_password(password):
    """
    QUÉ HACE:
        Revisa que una contraseña tenga una complejidad mínima.

    CÓMO FUNCIONA:
        Exige al menos 8 caracteres, una mayúscula, una minúscula, un número
        y un carácter especial. Devuelve (True, "") si cumple o (False, motivo)
        si debe corregirse.
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not any(c.isupper() for c in password):
        return False, "Debe incluir al menos una letra mayúscula."
    if not any(c.islower() for c in password):
        return False, "Debe incluir al menos una letra minúscula."
    if not any(c.isdigit() for c in password):
        return False, "Debe incluir al menos un número."
    if not any(not c.isalnum() for c in password):
        return False, "Debe incluir al menos un carácter especial."
    return True, ""


def generar_hash_password(password, salt=None):
    """
    QUÉ HACE:
        Convierte la contraseña en un hash seguro para no guardarla en texto plano.

    CÓMO FUNCIONA:
        Usa PBKDF2-HMAC-SHA256 con una sal aleatoria y 300 000 iteraciones.
        El resultado es un valor derivado que se puede comparar al iniciar sesión,
        pero no permite recuperar directamente la contraseña original.
    """
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
        dklen=32,
    )
    return salt, password_hash


def verificar_password(password, salt_b64, hash_b64):
    """
    QUÉ HACE:
        Comprueba si la contraseña escrita por el usuario coincide con la registrada.

    CÓMO FUNCIONA:
        Decodifica la sal almacenada, vuelve a aplicar PBKDF2 a la contraseña
        ingresada y compara el resultado mediante hmac.compare_digest para evitar
        comparaciones inseguras.
    """
    salt = base64.b64decode(salt_b64)
    expected_hash = base64.b64decode(hash_b64)
    _, actual_hash = generar_hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def derivar_clave_mfa(password, salt):
    """
    QUÉ HACE:
        Deriva una clave de cifrado independiente para proteger el secreto MFA.

    CÓMO FUNCIONA:
        Usa PBKDF2 con la contraseña del propio usuario y una variante de su sal.
        La clave resultante se adapta al formato requerido por Fernet.
    """
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt + b"-MFA",
        PASSWORD_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(derived)


def cifrar_secreto_mfa(secret, password, salt):
    """
    QUÉ HACE:
        Cifra el secreto TOTP antes de guardarlo en la base de datos.

    CÓMO FUNCIONA:
        Deriva una clave a partir de la contraseña del usuario y cifra el secreto
        mediante Fernet. Así, el secreto MFA no queda guardado directamente.
    """
    fernet = Fernet(derivar_clave_mfa(password, salt))
    return fernet.encrypt(secret.encode("utf-8")).decode("utf-8")


def descifrar_secreto_mfa(secret_enc, password, salt):
    """
    QUÉ HACE:
        Recupera temporalmente el secreto MFA del usuario durante el inicio de sesión.

    CÓMO FUNCIONA:
        Deriva nuevamente la misma clave usando la contraseña correcta y descifra
        el token Fernet almacenado. El secreto se usa únicamente para validar TOTP.
    """
    fernet = Fernet(derivar_clave_mfa(password, salt))
    return fernet.decrypt(secret_enc.encode("utf-8")).decode("utf-8")


# ============================================================
# AUTENTICACIÓN MULTIFACTOR TOTP
# ============================================================

def generar_secreto_mfa():
    """
    QUÉ HACE:
        Genera un secreto aleatorio para el segundo factor de autenticación.

    CÓMO FUNCIONA:
        Produce 20 bytes criptográficamente aleatorios y los convierte a Base32,
        formato compatible con aplicaciones como Google Authenticator, Microsoft
        Authenticator o Authy.
    """
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def calcular_totp(secret, momento=None, intervalo=30, digitos=6):
    """
    QUÉ HACE:
        Calcula el código TOTP de 6 dígitos correspondiente al momento actual.

    CÓMO FUNCIONA:
        Implementa el estándar TOTP con HMAC-SHA1. Divide el tiempo en ventanas de
        30 segundos, calcula un HMAC con el secreto y obtiene el código dinámico.
        El usuario ve el mismo código en su aplicación autenticadora.
    """
    if momento is None:
        momento = int(time.time())

    contador = int(momento // intervalo)
    padding_needed = (8 - len(secret) % 8) % 8
    secret_padded = secret + ("=" * padding_needed)
    key = base64.b32decode(secret_padded, casefold=True)

    msg = struct.pack(">Q", contador)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digitos)).zfill(digitos)


def verificar_totp(secret, codigo):
    """
    QUÉ HACE:
        Valida el código MFA digitado por el usuario.

    CÓMO FUNCIONA:
        Comprueba la ventana actual de 30 segundos y también una ventana anterior
        y una posterior para tolerar pequeñas diferencias de reloj entre equipos.
    """
    codigo = codigo.strip()
    if not (codigo.isdigit() and len(codigo) == 6):
        return False

    ahora = int(time.time())
    for desplazamiento in (-30, 0, 30):
        esperado = calcular_totp(secret, ahora + desplazamiento)
        if hmac.compare_digest(esperado, codigo):
            return True
    return False


def mostrar_secreto_mfa(username, secret):
    """
    QUÉ HACE:
        Muestra el secreto MFA de un usuario recién creado para poder configurarlo.

    CÓMO FUNCIONA:
        Abre una ventana con el secreto Base32. El usuario debe agregar manualmente
        ese secreto en una aplicación autenticadora y guardar allí su segundo factor.
        El programa no vuelve a mostrarlo después de cerrar esta ventana.
    """
    ventana = tk.Toplevel(root)
    ventana.title("Configurar MFA")
    ventana.geometry("560x230")
    ventana.grab_set()

    tk.Label(
        ventana,
        text=f"Configurar MFA para: {username}",
        font=("Arial", 12, "bold"),
    ).pack(pady=(15, 8))

    tk.Label(
        ventana,
        text=(
            "En Google Authenticator,\n"
            "agregue una cuenta manual e introduzca este secreto:"
        ),
        justify="center",
    ).pack()

    entrada = tk.Entry(ventana, width=55, justify="center")
    entrada.insert(0, secret)
    entrada.config(state="readonly")
    entrada.pack(pady=12)

    tk.Label(
        ventana,
        text="Tipo: basado en tiempo (TOTP) | Dígitos: 6 | Intervalo: 30 segundos",
        fg="gray",
    ).pack()

    tk.Button(ventana, text="Ya lo configuré", command=ventana.destroy).pack(pady=15)
    ventana.wait_window()


# ============================================================
# BÓVEDA Y PROTECCIÓN DE DATOS
# ============================================================

def derivar_clave_vault(vault_password, salt):
    """
    QUÉ HACE:
        Convierte la contraseña maestra institucional en una clave de cifrado.

    CÓMO FUNCIONA:
        Aplica PBKDF2-HMAC-SHA256 con una sal propia del sistema. La clave derivada
        se usa con Fernet para cifrar los datos personales almacenados.
    """
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        vault_password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(derived)


def cargar_configuracion():
    """
    QUÉ HACE:
        Lee la configuración criptográfica general del sistema.

    CÓMO FUNCIONA:
        Abre falconsigned_config.json y devuelve su contenido como diccionario.
        Este archivo no almacena la contraseña maestra; almacena únicamente una
        sal y un token cifrado usado para comprobar si la contraseña es correcta.
    """
    if not CONFIG_PATH.exists():
        return None
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def crear_configuracion_vault(vault_password):
    """
    QUÉ HACE:
        Inicializa la bóveda criptográfica la primera vez que se ejecuta el sistema.

    CÓMO FUNCIONA:
        Genera una sal aleatoria, deriva una clave Fernet y cifra una frase de
        verificación. Solo se guarda el token cifrado, nunca la contraseña maestra.
    """
    salt = secrets.token_bytes(16)
    fernet = Fernet(derivar_clave_vault(vault_password, salt))
    check_token = fernet.encrypt(b"FALCON-VAULT-OK").decode("utf-8")

    config = {
        "vault_salt": base64.b64encode(salt).decode("utf-8"),
        "vault_check": check_token,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)


def validar_vault_password(vault_password):
    """
    QUÉ HACE:
        Comprueba si la contraseña maestra institucional es correcta.

    CÓMO FUNCIONA:
        Deriva la clave a partir de la contraseña ingresada e intenta descifrar el
        token de comprobación. Si recupera 'FALCON-VAULT-OK', la contraseña es válida.
    """
    config = cargar_configuracion()
    if not config:
        return False

    salt = base64.b64decode(config["vault_salt"])
    fernet = Fernet(derivar_clave_vault(vault_password, salt))

    try:
        valor = fernet.decrypt(config["vault_check"].encode("utf-8"))
        return valor == b"FALCON-VAULT-OK"
    except InvalidToken:
        return False


def obtener_fernet_vault(vault_password):
    """
    QUÉ HACE:
        Construye el objeto Fernet que cifra y descifra los datos protegidos.

    CÓMO FUNCIONA:
        Recupera la sal de configuración y deriva la misma clave a partir de la
        contraseña maestra correcta.
    """
    config = cargar_configuracion()
    salt = base64.b64decode(config["vault_salt"])
    return Fernet(derivar_clave_vault(vault_password, salt))


def cifrar_dato(texto, vault_password):
    """
    QUÉ HACE:
        Cifra información sensible antes de almacenarla.

    CÓMO FUNCIONA:
        Usa Fernet y la clave derivada de la contraseña maestra. Se utiliza para
        proteger nombre del estudiante, carné y tipo de documento.
    """
    fernet = obtener_fernet_vault(vault_password)
    return fernet.encrypt(texto.encode("utf-8")).decode("utf-8")


def descifrar_dato(token, vault_password):
    """
    QUÉ HACE:
        Descifra un dato sensible almacenado por FalconSigned.

    CÓMO FUNCIONA:
        Usa la misma clave Fernet derivada de la contraseña maestra y devuelve el
        texto original únicamente mientras el sistema está autorizado.
    """
    fernet = obtener_fernet_vault(vault_password)
    return fernet.decrypt(token.encode("utf-8")).decode("utf-8")


def solicitar_vault_password():
    """
    QUÉ HACE:
        Solicita y valida la contraseña maestra cuando se necesita la clave privada.

    CÓMO FUNCIONA:
        Pide la contraseña mediante una ventana oculta. Si es correcta, la conserva
        únicamente en memoria durante la sesión actual para no solicitarla en cada
        operación. Al cerrar sesión se elimina de la variable de sesión.
    """
    global vault_password_session

    if vault_password_session and validar_vault_password(vault_password_session):
        return vault_password_session

    password = simpledialog.askstring(
        "Bóveda institucional",
        "Ingrese la contraseña maestra de la bóveda:",
        show="*",
        parent=root,
    )

    if not password:
        return None

    if not validar_vault_password(password):
        messagebox.showerror("Acceso denegado", "Contraseña maestra incorrecta.")
        return None

    vault_password_session = password
    return password


# ============================================================
# CLAVES RSA: GENERACIÓN, PERSISTENCIA, ROTACIÓN Y REVOCACIÓN
# ============================================================

def generar_id_clave():
    """
    QUÉ HACE:
        Crea un identificador único para cada versión de clave institucional.

    CÓMO FUNCIONA:
        Usa fecha y hora para producir identificadores como KEY-20260807-141830.
        Ese identificador se almacena con cada documento firmado.
    """
    return datetime.now().strftime("KEY-%Y%m%d-%H%M%S")


def generar_y_guardar_clave(vault_password):
    """
    QUÉ HACE:
        Genera una nueva pareja de claves RSA y la guarda de forma persistente.

    CÓMO FUNCIONA:
        - Genera RSA de 2048 bits.
        - La clave privada se guarda cifrada con la contraseña maestra mediante
          PKCS#8 + BestAvailableEncryption.
        - La clave pública se guarda en PEM sin secreto, porque debe poder usarse
          para verificar firmas.
        - Registra la nueva clave como 'Activa' en la base de datos.
    """
    key_id = generar_id_clave()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_path = KEYS_DIR / f"{key_id}_private.pem"
    public_path = KEYS_DIR / f"{key_id}_public.pem"

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            vault_password.encode("utf-8")
        ),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    with conectar_db() as conn:
        conn.execute(
            """
            INSERT INTO keys (key_id, private_key_path, public_key_path, created_at, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                key_id,
                str(private_path),
                str(public_path),
                datetime.now().isoformat(timespec="seconds"),
                "Activa",
            ),
        )

    return key_id


def obtener_clave_activa():
    """
    QUÉ HACE:
        Obtiene la clave institucional que actualmente está habilitada para firmar.

    CÓMO FUNCIONA:
        Consulta la tabla keys buscando el registro con estado 'Activa'.
    """
    with conectar_db() as conn:
        return conn.execute(
            "SELECT * FROM keys WHERE status = 'Activa' ORDER BY id DESC LIMIT 1"
        ).fetchone()


def cargar_clave_privada(key_row, vault_password):
    """
    QUÉ HACE:
        Carga en memoria una clave privada RSA protegida.

    CÓMO FUNCIONA:
        Lee el archivo PEM cifrado correspondiente a la clave y lo descifra usando
        la contraseña maestra. La clave privada nunca se almacena en texto plano.
    """
    pem = Path(key_row["private_key_path"]).read_bytes()
    return serialization.load_pem_private_key(
        pem,
        password=vault_password.encode("utf-8"),
    )


def cargar_clave_publica(key_id):
    """
    QUÉ HACE:
        Carga la clave pública asociada a una firma específica.

    CÓMO FUNCIONA:
        Busca el key_id en la base de datos, lee el PEM público y construye el
        objeto criptográfico usado para verificar la firma.
    """
    with conectar_db() as conn:
        key_row = conn.execute(
            "SELECT * FROM keys WHERE key_id = ?",
            (key_id,),
        ).fetchone()

    if not key_row:
        return None, None

    pem = Path(key_row["public_key_path"]).read_bytes()
    public_key = serialization.load_pem_public_key(pem)
    return public_key, key_row


def rotar_clave():
    """
    QUÉ HACE:
        Reemplaza la clave activa por una nueva sin destruir la anterior.

    CÓMO FUNCIONA:
        Marca la clave actual como 'Retirada', genera una nueva pareja RSA y la
        registra como 'Activa'. Las firmas antiguas pueden seguir verificándose con
        la clave pública retirada porque dicha clave permanece almacenada.
    """
    if not usuario_actual or usuario_actual["role"] != "admin":
        messagebox.showerror("Permiso denegado", "Solo un administrador puede rotar claves.")
        return

    vault_password = solicitar_vault_password()
    if not vault_password:
        return

    key_actual = obtener_clave_activa()
    with conectar_db() as conn:
        if key_actual:
            conn.execute(
                "UPDATE keys SET status = 'Retirada' WHERE key_id = ?",
                (key_actual["key_id"],),
            )

    nueva = generar_y_guardar_clave(vault_password)
    registrar_auditoria(usuario_actual["username"], "ROTACION_CLAVE", f"Nueva clave: {nueva}")
    messagebox.showinfo("Rotación completada", f"Nueva clave activa:\n{nueva}")
    actualizar_estado_clave()


def revocar_clave():
    """
    QUÉ HACE:
        Invalida una clave que se considera comprometida.

    CÓMO FUNCIONA:
        El administrador indica el key_id. La clave pasa al estado 'Revocada'.
        Si era la clave activa, FalconSigned genera automáticamente una nueva clave
        para impedir que el sistema continúe firmando con la clave comprometida.
    """
    if not usuario_actual or usuario_actual["role"] != "admin":
        messagebox.showerror("Permiso denegado", "Solo un administrador puede revocar claves.")
        return

    key_id = simpledialog.askstring(
        "Revocar clave",
        "Ingrese el identificador de la clave (KEY-...):",
        parent=root,
    )
    if not key_id:
        return

    with conectar_db() as conn:
        key_row = conn.execute(
            "SELECT * FROM keys WHERE key_id = ?",
            (key_id.strip(),),
        ).fetchone()

    if not key_row:
        messagebox.showerror("No encontrada", "No existe una clave con ese identificador.")
        return

    if key_row["status"] == "Revocada":
        messagebox.showinfo("Información", "La clave ya se encuentra revocada.")
        return

    confirmar = messagebox.askyesno(
        "Confirmar revocación",
        "Una clave revocada hará que sus firmas se consideren no confiables.\n\n¿Desea continuar?",
    )
    if not confirmar:
        return

    era_activa = key_row["status"] == "Activa"

    with conectar_db() as conn:
        conn.execute(
            "UPDATE keys SET status = 'Revocada' WHERE key_id = ?",
            (key_row["key_id"],),
        )

    nueva_clave = None
    if era_activa:
        vault_password = solicitar_vault_password()
        if not vault_password:
            messagebox.showwarning(
                "Clave revocada",
                "La clave fue revocada, pero no se creó una nueva porque no se desbloqueó la bóveda.",
            )
        else:
            nueva_clave = generar_y_guardar_clave(vault_password)

    detalle = f"Clave revocada: {key_row['key_id']}"
    if nueva_clave:
        detalle += f" | Reemplazo: {nueva_clave}"

    registrar_auditoria(usuario_actual["username"], "REVOCACION_CLAVE", detalle)
    messagebox.showinfo("Revocación", detalle)
    actualizar_estado_clave()


# ============================================================
# DOCUMENTOS, HASH Y FIRMA DIGITAL
# ============================================================

def seleccionar_archivo():
    """
    QUÉ HACE:
        Permite seleccionar el PDF que será firmado o verificado.

    CÓMO FUNCIONA:
        Abre el explorador de archivos con filedialog y guarda la ruta seleccionada
        en la variable global archivo_seleccionado.
    """
    global archivo_seleccionado

    archivo_seleccionado = filedialog.askopenfilename(
        title="Seleccionar documento",
        filetypes=[("Documentos PDF", "*.pdf"), ("Todos los archivos", "*.*")],
    )

    if archivo_seleccionado:
        etiqueta_archivo.config(text=Path(archivo_seleccionado).name)
    else:
        etiqueta_archivo.config(text="Ningún archivo seleccionado")


def calcular_hash(ruta):
    """
    QUÉ HACE:
        Calcula la huella digital SHA-256 del documento.

    CÓMO FUNCIONA:
        Lee el archivo por bloques para no cargar documentos grandes completamente
        en memoria. Cada bloque actualiza SHA-256 y finalmente devuelve 32 bytes.
    """
    sha256 = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(bloque)
    return sha256.digest()


# ============================================================
# CIFRADO AES-256-GCM Y PROTECCIÓN DE CLAVE CON RSA-OAEP
# ============================================================


def cifrar_documento_aes(ruta):
    """
    QUÉ HACE:
    Cifra el contenido del documento utilizando AES-256-GCM.
    """
    clave_aes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(clave_aes)

    nonce = secrets.token_bytes(12)

    with open(ruta, "rb") as f:
        contenido = f.read()

    contenido_cifrado = aesgcm.encrypt(
        nonce,
        contenido,
        None
    )

    return clave_aes, nonce, contenido_cifrado


def descifrar_documento_aes(clave_aes, nonce, contenido_cifrado):
    """
    QUÉ HACE:
    Descifra un documento protegido con AES-256-GCM.
    """
    aesgcm = AESGCM(clave_aes)

    contenido_original = aesgcm.decrypt(
        nonce,
        contenido_cifrado,
        None
    )

    return contenido_original


def proteger_clave_aes(clave_aes, clave_publica):
    """
    QUÉ HACE:
    Protege la clave AES utilizando RSA-OAEP.
    """
    return clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def recuperar_clave_aes(clave_protegida, clave_privada):
    """
    QUÉ HACE:
    Recupera la clave AES utilizando la clave privada RSA.
    """
    return clave_privada.decrypt(
        clave_protegida,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def generar_codigo_documento():
    """
    QUÉ HACE:
        Genera el código consecutivo visible del documento firmado.

    CÓMO FUNCIONA:
        Cuenta cuántos documentos se han registrado en el año actual y genera
        códigos como FALCON-2026-00001.
    """
    anio = datetime.now().year
    prefijo = f"FALCON-{anio}-"

    with conectar_db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS total FROM documents WHERE code LIKE ?",
            (f"{prefijo}%",),
        ).fetchone()["total"]

    return f"{prefijo}{total + 1:05d}"


def firmar_documento():
    """
    QUÉ HACE:
        Firma digitalmente un documento académico y registra la evidencia.

    CÓMO FUNCIONA:
        1. Verifica que el usuario tenga permiso para firmar.
        2. Valida los datos y el archivo.
        3. Desbloquea la bóveda institucional.
        4. Calcula SHA-256 del archivo.
        5. Firma ese hash con RSA-PSS y SHA-256 usando Prehashed, evitando el
           doble hash que existía en el prototipo original.
        6. Cifra los datos personales con Fernet.
        7. Guarda hash, firma, clave utilizada, firmante, fecha y estado.
    """
    if not usuario_actual or usuario_actual["role"] not in ("admin", "firmante"):
        messagebox.showerror("Permiso denegado", "Su usuario no tiene permiso para firmar documentos.")
        return

    if not archivo_seleccionado:
        messagebox.showerror("Error", "Seleccione un documento PDF.")
        return

    estudiante = entrada_nombre.get().strip()
    carne = entrada_carne.get().strip()
    tipo_documento = entrada_tipo.get().strip()

    if not estudiante or not carne or not tipo_documento:
        messagebox.showerror("Datos incompletos", "Complete estudiante, carné y tipo de documento.")
        return

    vault_password = solicitar_vault_password()
    if not vault_password:
        return

    key_row = obtener_clave_activa()
    if not key_row:
        messagebox.showerror("Error criptográfico", "No existe una clave institucional activa.")
        return

    try:
        private_key = cargar_clave_privada(key_row, vault_password)
    except (ValueError, TypeError):
        messagebox.showerror("Error", "No fue posible desbloquear la clave privada.")
        return

    hash_doc = calcular_hash(archivo_seleccionado)

    firma = private_key.sign(
        hash_doc,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )

    # Cifrar el documento con AES-256-GCM
    clave_aes, nonce, contenido_cifrado = cifrar_documento_aes(
    archivo_seleccionado
)

# Proteger la clave AES con RSA-OAEP
    public_key = private_key.public_key()
    clave_aes_protegida = proteger_clave_aes(
    clave_aes,
    public_key
)








    codigo = generar_codigo_documento()

    # GUARGA EL DOCUMENTO CIFRADO
    ruta_cifrada = ENCRYPTED_DIR / f"{codigo}.enc"

    with open(ruta_cifrada, "wb") as f:
     f.write(contenido_cifrado)
    student_enc = cifrar_dato(estudiante, vault_password)
    carne_enc = cifrar_dato(carne, vault_password)
    type_enc = cifrar_dato(tipo_documento, vault_password)

    with conectar_db() as conn:
        conn.execute(
            """
           INSERT INTO documents (
    code, student_enc, carne_enc, document_type_enc,
    original_name, encrypted_path, nonce_b64, encrypted_key_b64,
    hash_hex, signature_b64, key_id,
    signed_by, signed_at, status
)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                codigo,
                student_enc,
                carne_enc,
                type_enc,
                Path(archivo_seleccionado).name,
                str(ruta_cifrada),
base64.b64encode(nonce).decode("utf-8"),
base64.b64encode(clave_aes_protegida).decode("utf-8"),
                hash_doc.hex(),
                base64.b64encode(firma).decode("utf-8"),
                key_row["key_id"],
                usuario_actual["username"],
                datetime.now().isoformat(timespec="seconds"),
                "Vigente",
            ),
        )

    registrar_auditoria(
        usuario_actual["username"],
        "FIRMA_DOCUMENTO",
        f"Código: {codigo} | Clave: {key_row['key_id']}",
    )

    entrada_codigo_verificar.delete(0, tk.END)
    entrada_codigo_verificar.insert(0, codigo)
    etiqueta_estado.config(text=f"Documento firmado correctamente: {codigo}")

    messagebox.showinfo(
        "Documento firmado",
        f"Firma creada correctamente.\n\nCódigo: {codigo}\nClave: {key_row['key_id']}",
    )


def verificar_documento():
    """
    QUÉ HACE:
        Comprueba la integridad, autenticidad y vigencia de un documento firmado.

    CÓMO FUNCIONA:
        1. Busca el registro por código FalconSigned.
        2. Calcula el SHA-256 del archivo seleccionado.
        3. Compara el hash actual con el hash registrado.
        4. Recupera la firma almacenada y la clave pública de la versión usada.
        5. Verifica RSA-PSS.
        6. Revisa si el documento o la clave fueron revocados.
    """
    if not archivo_seleccionado:
        messagebox.showerror("Error", "Seleccione el PDF que desea verificar.")
        return

    codigo = entrada_codigo_verificar.get().strip()
    if not codigo:
        messagebox.showerror("Error", "Ingrese el código FALCON del documento.")
        return

    with conectar_db() as conn:
        doc = conn.execute(
            "SELECT * FROM documents WHERE code = ?",
            (codigo,),
        ).fetchone()

    if not doc:
        messagebox.showerror("No encontrado", "No existe un documento registrado con ese código.")
        return

    hash_actual = calcular_hash(archivo_seleccionado)
    hash_registrado = bytes.fromhex(doc["hash_hex"])

    if not hmac.compare_digest(hash_actual, hash_registrado):
        registrar_auditoria(
            usuario_actual["username"],
            "VERIFICACION_FALLIDA",
            f"Código: {codigo} | Motivo: hash diferente",
        )
        messagebox.showerror(
            "ALERTA DE INTEGRIDAD",
            "El archivo fue modificado o no corresponde al documento registrado.\n\n"
            "El hash SHA-256 no coincide.",
        )
        return

    public_key, key_row = cargar_clave_publica(doc["key_id"])
    if not public_key or not key_row:
        messagebox.showerror("Error", "No se encontró la clave pública asociada a la firma.")
        return

    firma = base64.b64decode(doc["signature_b64"])

    try:
        public_key.verify(
            firma,
            hash_actual,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
    except Exception:
        registrar_auditoria(
            usuario_actual["username"],
            "VERIFICACION_FALLIDA",
            f"Código: {codigo} | Motivo: firma inválida",
        )
        messagebox.showerror(
            "Firma inválida",
            "La firma RSA-PSS no pudo ser validada.",
        )
        return

    if doc["status"] == "Revocado":
        resultado = (
            "FIRMA CRIPTOGRÁFICAMENTE CORRECTA, PERO DOCUMENTO REVOCADO\n\n"
            f"Código: {codigo}\n"
            f"Firmado por: {doc['signed_by']}\n"
            f"Fecha: {doc['signed_at']}"
        )
        registrar_auditoria(usuario_actual["username"], "VERIFICACION_REVOCADO", f"Código: {codigo}")
        messagebox.showwarning("Documento revocado", resultado)
        return

    if key_row["status"] == "Revocada":
        resultado = (
            "LA FIRMA MATEMÁTICAMENTE COINCIDE, PERO LA CLAVE FUE REVOCADA\n\n"
            "Por seguridad, el documento no debe considerarse confiable.\n\n"
            f"Código: {codigo}\nClave: {doc['key_id']}"
        )
        registrar_auditoria(usuario_actual["username"], "VERIFICACION_CLAVE_REVOCADA", f"Código: {codigo}")
        messagebox.showwarning("Clave comprometida", resultado)
        return

    registrar_auditoria(
        usuario_actual["username"],
        "VERIFICACION_EXITOSA",
        f"Código: {codigo}",
    )

    messagebox.showinfo(
        "DOCUMENTO ACADÉMICO VÁLIDO",
        "La firma digital es válida.\n"
        "El documento no presenta modificaciones.\n\n"
        f"Código: {codigo}\n"
        f"Firmado por: {doc['signed_by']}\n"
        f"Fecha: {doc['signed_at']}\n"
        f"Clave: {doc['key_id']} ({key_row['status']})",
    )

def descifrar_documento():
    """
    QUÉ HACE:
    Descifra un documento protegido con AES-256-GCM.

    CÓMO FUNCIONA:
        1. Busca el documento mediante su código.
        2. Busca la clave RSA utilizada para ese documento.
        3. Recupera la clave AES mediante RSA-OAEP.
        4. Descifra el archivo utilizando AES-256-GCM.
    """
    codigo = entrada_codigo_verificar.get().strip()

    if not codigo:
        messagebox.showerror(
            "Error",
            "Ingrese el código FALCON del documento."
        )
        return

    with conectar_db() as conn:
        doc = conn.execute(
            "SELECT * FROM documents WHERE code = ?",
            (codigo,),
        ).fetchone()

        if not doc:
            messagebox.showerror(
                "No encontrado",
                "No existe un documento con ese código."
            )
            return

        key_row = conn.execute(
            "SELECT * FROM keys WHERE key_id = ?",
            (doc["key_id"],),
        ).fetchone()

    if not key_row:
        messagebox.showerror(
            "Error",
            "No se encontró la clave asociada al documento."
        )
        return

    try:
        vault_password = solicitar_vault_password()

        if not vault_password:
            return

        private_key = cargar_clave_privada(
            key_row,
            vault_password
        )

        clave_protegida = base64.b64decode(
            doc["encrypted_key_b64"]
        )

        nonce = base64.b64decode(
            doc["nonce_b64"]
        )

        clave_aes = recuperar_clave_aes(
            clave_protegida,
            private_key
        )

        ruta_cifrada = Path(doc["encrypted_path"])

        with open(ruta_cifrada, "rb") as f:
            contenido_cifrado = f.read()

        contenido_original = descifrar_documento_aes(
            clave_aes,
            nonce,
            contenido_cifrado
        )

        ruta_salida = BASE_DIR / f"descifrado_{codigo}.pdf"

        with open(ruta_salida, "wb") as f:
            f.write(contenido_original)

        registrar_auditoria(
            usuario_actual["username"],
            "DESCIFRADO_DOCUMENTO",
            f"Código: {codigo}"
        )

        messagebox.showinfo(
            "Descifrado exitoso",
            "El documento fue descifrado correctamente.\n\n"
            f"Archivo recuperado:\n{ruta_salida}"
        )

    except Exception as e:
        messagebox.showerror(
            "Error de descifrado",
            f"No fue posible descifrar el documento.\n\n{e}"
        )




def revocar_documento():
    """
    QUÉ HACE:
        Cambia un documento de estado 'Vigente' a 'Revocado'.

    CÓMO FUNCIONA:
        Un administrador introduce el código FALCON. El documento sigue conservando
        su firma para fines de evidencia, pero la verificación avisa que ya no debe
        considerarse vigente.
    """
    if not usuario_actual or usuario_actual["role"] != "admin":
        messagebox.showerror("Permiso denegado", "Solo un administrador puede revocar documentos.")
        return

    codigo = simpledialog.askstring(
        "Revocar documento",
        "Ingrese el código FALCON del documento:",
        parent=root,
    )
    if not codigo:
        return

    with conectar_db() as conn:
        doc = conn.execute(
            "SELECT * FROM documents WHERE code = ?",
            (codigo.strip(),),
        ).fetchone()

        if not doc:
            messagebox.showerror("No encontrado", "No existe un documento con ese código.")
            return

        conn.execute(
            "UPDATE documents SET status = 'Revocado' WHERE code = ?",
            (codigo.strip(),),
        )

    registrar_auditoria(usuario_actual["username"], "REVOCACION_DOCUMENTO", f"Código: {codigo.strip()}")
    messagebox.showinfo("Documento revocado", f"El documento {codigo.strip()} fue revocado.")


# ============================================================
# GESTIÓN DE USUARIOS
# ============================================================

def crear_usuario_en_db(username, password, role):
    """
    QUÉ HACE:
        Registra un nuevo usuario con contraseña protegida, rol y MFA.

    CÓMO FUNCIONA:
        - Genera una sal aleatoria.
        - Deriva el hash PBKDF2 de la contraseña.
        - Genera un secreto TOTP.
        - Cifra el secreto TOTP con una clave derivada de la contraseña del usuario.
        - Guarda únicamente valores protegidos en la base de datos.
        - Si el rol solicitado es auditor, verifica que no exista otro auditor activo.
    """
    if role == "auditor":
        with conectar_db() as conn:
            auditor_existente = conn.execute(
                "SELECT id FROM users WHERE role = 'auditor' AND active = 1 LIMIT 1"
            ).fetchone()
        if auditor_existente:
            raise ValueError(
                "Ya existe un usuario auditor activo. FalconSigned permite un único auditor."
            )

    salt, password_hash = generar_hash_password(password)
    secret = generar_secreto_mfa()
    secret_enc = cifrar_secreto_mfa(secret, password, salt)

    with conectar_db() as conn:
        conn.execute(
            """
            INSERT INTO users (
                username, password_salt, password_hash, mfa_secret_enc,
                role, active, failed_attempts, created_at
            )
            VALUES (?, ?, ?, ?, ?, 1, 0, ?)
            """,
            (
                username,
                base64.b64encode(salt).decode("utf-8"),
                base64.b64encode(password_hash).decode("utf-8"),
                secret_enc,
                role,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )

    return secret


def crear_usuario_gui():
    """
    QUÉ HACE:
        Permite que un administrador cree usuarios desde la interfaz.

    CÓMO FUNCIONA:
        Abre una ventana para introducir usuario, contraseña y rol. Tras validar
        la contraseña, crea el usuario y muestra su secreto MFA para configurarlo.
    """
    if not usuario_actual or usuario_actual["role"] != "admin":
        messagebox.showerror("Permiso denegado", "Solo un administrador puede crear usuarios.")
        return

    ventana = tk.Toplevel(root)
    ventana.title("Crear usuario")
    ventana.geometry("420x320")
    ventana.grab_set()

    tk.Label(ventana, text="Nuevo usuario", font=("Arial", 14, "bold")).pack(pady=12)

    tk.Label(ventana, text="Nombre de usuario").pack()
    e_user = tk.Entry(ventana, width=32)
    e_user.pack(pady=4)

    tk.Label(ventana, text="Contraseña").pack()
    e_pass = tk.Entry(ventana, width=32, show="*")
    e_pass.pack(pady=4)

    tk.Label(ventana, text="Rol").pack()
    combo = ttk.Combobox(ventana, values=["admin", "firmante", "verificador", "auditor"], state="readonly")
    combo.set("verificador")
    combo.pack(pady=4)

    def guardar():
        username = e_user.get().strip()
        password = e_pass.get()
        role = combo.get()

        if not username or not password or not role:
            messagebox.showerror("Error", "Complete todos los campos.", parent=ventana)
            return

        ok, motivo = validar_fortaleza_password(password)
        if not ok:
            messagebox.showerror("Contraseña débil", motivo, parent=ventana)
            return

        try:
            secret = crear_usuario_en_db(username, password, role)
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Ese nombre de usuario ya existe.", parent=ventana)
            return
        except ValueError as e:
            messagebox.showerror("Error", str(e), parent=ventana)
            return

        registrar_auditoria(usuario_actual["username"], "CREACION_USUARIO", f"Usuario: {username} | Rol: {role}")
        ventana.destroy()
        mostrar_secreto_mfa(username, secret)

    tk.Button(ventana, text="Crear usuario", command=guardar).pack(pady=18)


def autenticar_usuario(username, password, codigo_mfa):
    """
    QUÉ HACE:
        Valida las tres condiciones de acceso: usuario, contraseña y MFA.

    CÓMO FUNCIONA:
        1. Busca el usuario.
        2. Comprueba si está activo o temporalmente bloqueado.
        3. Valida PBKDF2 de la contraseña.
        4. Descifra el secreto MFA usando la contraseña correcta.
        5. Valida el TOTP.
        6. Reinicia los intentos fallidos cuando el acceso es exitoso.

        También implementa bloqueo temporal después de varios intentos incorrectos.
    """
    with conectar_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not user:
        return False, "Usuario, contraseña o MFA incorrectos.", None

    if not user["active"]:
        return False, "El usuario está deshabilitado.", None

    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.now() < locked_until:
            segundos = int((locked_until - datetime.now()).total_seconds())
            return False, f"Usuario bloqueado temporalmente. Espere {segundos} segundos.", None

    password_ok = verificar_password(password, user["password_salt"], user["password_hash"])

    if not password_ok:
        registrar_intento_fallido(user)
        return False, "Usuario, contraseña o MFA incorrectos.", None

    try:
        salt = base64.b64decode(user["password_salt"])
        secret = descifrar_secreto_mfa(user["mfa_secret_enc"], password, salt)
    except InvalidToken:
        registrar_intento_fallido(user)
        return False, "No fue posible validar el segundo factor.", None

    if not verificar_totp(secret, codigo_mfa):
        registrar_intento_fallido(user)
        return False, "Usuario, contraseña o MFA incorrectos.", None

    with conectar_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        user_actualizado = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()

    return True, "Acceso correcto.", user_actualizado


def registrar_intento_fallido(user):
    """
    QUÉ HACE:
        Cuenta los intentos de inicio de sesión incorrectos y aplica bloqueo temporal.

    CÓMO FUNCIONA:
        Incrementa failed_attempts. Al llegar a 5 intentos, establece locked_until
        un minuto en el futuro y reinicia el contador.
    """
    intentos = user["failed_attempts"] + 1
    locked_until = None

    if intentos >= MAX_FAILED_ATTEMPTS:
        locked_until = (datetime.now() + timedelta(seconds=LOCKOUT_SECONDS)).isoformat(timespec="seconds")
        intentos = 0

    with conectar_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (intentos, locked_until, user["id"]),
        )


# ============================================================
# CONFIGURACIÓN INICIAL
# ============================================================

def sistema_requiere_configuracion():
    """
    QUÉ HACE:
        Determina si FalconSigned se está ejecutando por primera vez.

    CÓMO FUNCIONA:
        Verifica que exista la configuración de bóveda y al menos un usuario.
    """
    if not CONFIG_PATH.exists():
        return True

    with conectar_db() as conn:
        total = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
    return total == 0


def configuracion_inicial():
    """
    QUÉ HACE:
        Prepara FalconSigned en su primera ejecución.

    CÓMO FUNCIONA:
        Solicita:
        - usuario administrador inicial,
        - contraseña segura del administrador,
        - contraseña maestra de la bóveda.

        Después crea el usuario, configura MFA, crea la bóveda y genera la primera
        pareja de claves RSA persistentes.
    """
    root.withdraw()

    messagebox.showinfo(
        "Configuración inicial",
        "FalconSigned se ejecuta por primera vez.\n\n"
        "Se creará el administrador inicial, la bóveda y la primera clave RSA.",
    )

    while True:
        username = simpledialog.askstring(
            "Administrador",
            "Cree el nombre de usuario administrador:",
            parent=root,
        )
        if username and username.strip():
            username = username.strip()
            break
        if username is None:
            return False

    while True:
        password = simpledialog.askstring(
            "Contraseña de administrador",
            "Cree una contraseña segura para el administrador:",
            show="*",
            parent=root,
        )
        if password is None:
            return False

        ok, motivo = validar_fortaleza_password(password)
        if not ok:
            messagebox.showerror("Contraseña débil", motivo)
            continue

        confirm = simpledialog.askstring(
            "Confirmar contraseña",
            "Repita la contraseña del administrador:",
            show="*",
            parent=root,
        )
        if password != confirm:
            messagebox.showerror("Error", "Las contraseñas no coinciden.")
            continue
        break

    while True:
        vault_password = simpledialog.askstring(
            "Contraseña maestra",
            "Cree la contraseña maestra de la bóveda institucional:\n\n"
            "Esta contraseña protege las claves privadas y los datos almacenados.",
            show="*",
            parent=root,
        )
        if vault_password is None:
            return False

        ok, motivo = validar_fortaleza_password(vault_password)
        if not ok:
            messagebox.showerror("Contraseña maestra débil", motivo)
            continue

        confirm_vault = simpledialog.askstring(
            "Confirmar contraseña maestra",
            "Repita la contraseña maestra:",
            show="*",
            parent=root,
        )
        if vault_password != confirm_vault:
            messagebox.showerror("Error", "Las contraseñas maestras no coinciden.")
            continue
        break

    crear_configuracion_vault(vault_password)
    secret = crear_usuario_en_db(username, password, "admin")
    key_id = generar_y_guardar_clave(vault_password)

    registrar_auditoria(username, "CONFIGURACION_INICIAL", f"Clave inicial: {key_id}")

    root.deiconify()
    mostrar_secreto_mfa(username, secret)
    messagebox.showinfo(
        "Configuración terminada",
        "La configuración inicial fue creada correctamente.\n\n"
        "Ahora inicie sesión con su usuario, contraseña y código MFA.",
    )
    return True


# ============================================================
# INTERFAZ: LOGIN, SESIÓN Y PERMISOS
# ============================================================

def iniciar_sesion():
    """
    QUÉ HACE:
        Procesa el formulario de acceso del usuario.

    CÓMO FUNCIONA:
        Toma usuario, contraseña y código MFA, llama a autenticar_usuario y, si los
        tres factores son válidos, guarda el usuario actual y abre el panel principal.
    """
    global usuario_actual

    username = login_user.get().strip()
    password = login_password.get()
    codigo = login_mfa.get().strip()

    if not username or not password or not codigo:
        messagebox.showerror("Datos incompletos", "Ingrese usuario, contraseña y código MFA.")
        return

    ok, mensaje, user = autenticar_usuario(username, password, codigo)

    if not ok:
        registrar_auditoria(username or "DESCONOCIDO", "LOGIN_FALLIDO", mensaje)
        messagebox.showerror("Acceso denegado", mensaje)
        return

    usuario_actual = user
    registrar_auditoria(usuario_actual["username"], "LOGIN_EXITOSO", f"Rol: {usuario_actual['role']}")

    login_password.delete(0, tk.END)
    login_mfa.delete(0, tk.END)
    mostrar_panel_principal()


def cerrar_sesion():
    """
    QUÉ HACE:
        Finaliza la sesión actual y vuelve a la pantalla de login.

    CÓMO FUNCIONA:
        Registra el cierre en auditoría, borra el usuario actual y elimina de memoria
        la contraseña maestra que pudiera haberse desbloqueado durante la sesión.
    """
    global usuario_actual, vault_password_session, archivo_seleccionado

    if usuario_actual:
        registrar_auditoria(usuario_actual["username"], "LOGOUT", "Cierre de sesión")

    usuario_actual = None
    vault_password_session = None
    archivo_seleccionado = ""
    etiqueta_archivo.config(text="Ningún archivo seleccionado")

    frame_main.pack_forget()
    frame_login.pack(fill="both", expand=True)


def aplicar_permisos():
    rol = usuario_actual["role"]

    boton_firmar.config(state="normal" if rol in ("admin", "firmante") else "disabled")

    boton_crear_usuario.pack_forget()
    boton_rotar_clave.pack_forget()
    boton_revocar_clave.pack_forget()
    boton_revocar_documento.pack_forget()
    boton_ver_auditoria.pack_forget()

    if rol == "admin":
        frame_admin.pack(fill="x", pady=10)
        boton_crear_usuario.pack(side="left", padx=5)
        boton_rotar_clave.pack(side="left", padx=5)
        boton_revocar_clave.pack(side="left", padx=5)
        boton_revocar_documento.pack(side="left", padx=5)

    elif rol == "auditor":
        frame_admin.pack(fill="x", pady=10)
        boton_ver_auditoria.pack(side="left", padx=5)

    else:
        frame_admin.pack_forget()


def mostrar_panel_principal():
    """
    QUÉ HACE:
        Muestra la pantalla principal después de un login válido.

    CÓMO FUNCIONA:
        Oculta el formulario de acceso, muestra el panel de documentos y aplica
        permisos de acuerdo con el rol autenticado.
    """
    frame_login.pack_forget()
    frame_main.pack(fill="both", expand=True)

    etiqueta_usuario.config(
        text=f"Usuario: {usuario_actual['username']}   |   Rol: {usuario_actual['role']}"
    )
    aplicar_permisos()
    actualizar_estado_clave()


def actualizar_estado_clave():
    """
    QUÉ HACE:
        Actualiza en pantalla cuál es la clave RSA activa.

    CÓMO FUNCIONA:
        Consulta la tabla de claves y muestra el identificador de la clave que se
        utilizará para la próxima firma.
    """
    key = obtener_clave_activa()
    if key:
        etiqueta_clave.config(text=f"Clave activa: {key['key_id']}")
    else:
        etiqueta_clave.config(text="Clave activa: NINGUNA")


def ver_auditoria():
    if not usuario_actual or usuario_actual["role"] != "auditor":
        messagebox.showerror(
            "Permiso denegado",
            "Solo el usuario con rol auditor puede consultar la bitácora de auditoría."
        )
        return

    with conectar_db() as conn:
        filas = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100"
        ).fetchall()

    ventana = tk.Toplevel(root)
    ventana.title("Bitácora de auditoría")
    ventana.geometry("850x450")

    texto = tk.Text(ventana, wrap="none")
    texto.pack(fill="both", expand=True)

    for fila in filas:
        texto.insert(
            tk.END,
            f"[{fila['created_at']}] {fila['username']} | {fila['action']} | {fila['details'] or ''}\n",
        )

    texto.config(state="disabled")


# ============================================================
# CREACIÓN DE LA INTERFAZ GRÁFICA
# ============================================================

root = tk.Tk()
root.title(APP_NAME)
root.geometry("760x700")
root.minsize(720, 650)

# ---------- Pantalla de login ----------
frame_login = tk.Frame(root, padx=40, pady=40)
frame_login.pack(fill="both", expand=True)


tk.Label(frame_login, text="FalconSigned", font=("Arial", 24, "bold")).pack(pady=(45, 5))
tk.Label(frame_login, text="Firma digital para documentos del sector educativo", fg="gray").pack(pady=(0, 30))


tk.Label(frame_login, text="Usuario").pack()
login_user = tk.Entry(frame_login, width=35)
login_user.pack(pady=5)


tk.Label(frame_login, text="Contraseña").pack()
login_password = tk.Entry(frame_login, width=35, show="*")
login_password.pack(pady=5)


tk.Label(frame_login, text="Código MFA (6 dígitos)").pack()
login_mfa = tk.Entry(frame_login, width=35)
login_mfa.pack(pady=5)


tk.Button(frame_login, text="Iniciar sesión", width=22, command=iniciar_sesion).pack(pady=20)

tk.Label(
    frame_login,
    text="El acceso requiere contraseña y un segundo factor TOTP.",
    fg="gray",
).pack()

# ---------- Panel principal ----------
frame_main = tk.Frame(root, padx=25, pady=20)

cabecera = tk.Frame(frame_main)
cabecera.pack(fill="x")

tk.Label(cabecera, text="FalconSigned", font=("Arial", 20, "bold")).pack(side="left")
tk.Button(cabecera, text="Cerrar sesión", command=cerrar_sesion).pack(side="right")

etiqueta_usuario = tk.Label(frame_main, text="", fg="gray")
etiqueta_usuario.pack(anchor="w", pady=(3, 2))

etiqueta_clave = tk.Label(frame_main, text="Clave activa: ...", fg="gray")
etiqueta_clave.pack(anchor="w", pady=(0, 15))

separador = ttk.Separator(frame_main, orient="horizontal")
separador.pack(fill="x", pady=5)

# Datos del documento
form = tk.Frame(frame_main)
form.pack(fill="x", pady=10)


tk.Label(form, text="Nombre del estudiante").grid(row=0, column=0, sticky="w", pady=5)
entrada_nombre = tk.Entry(form, width=45)
entrada_nombre.grid(row=0, column=1, sticky="w", padx=10)


tk.Label(form, text="Carné").grid(row=1, column=0, sticky="w", pady=5)
entrada_carne = tk.Entry(form, width=45)
entrada_carne.grid(row=1, column=1, sticky="w", padx=10)


tk.Label(form, text="Tipo de documento").grid(row=2, column=0, sticky="w", pady=5)
entrada_tipo = tk.Entry(form, width=45)
entrada_tipo.grid(row=2, column=1, sticky="w", padx=10)

# Selección de archivo
frame_archivo = tk.Frame(frame_main)
frame_archivo.pack(fill="x", pady=10)

tk.Button(frame_archivo, text="Seleccionar PDF", command=seleccionar_archivo).pack(side="left")
etiqueta_archivo = tk.Label(frame_archivo, text="Ningún archivo seleccionado", fg="gray")
etiqueta_archivo.pack(side="left", padx=12)

# Firma
boton_firmar = tk.Button(frame_main, text="Firmar documento", width=24, command=firmar_documento)
boton_firmar.pack(pady=8)

# Verificación
frame_verificacion = tk.LabelFrame(frame_main, text="Verificar documento", padx=12, pady=12)
frame_verificacion.pack(fill="x", pady=12)


tk.Label(frame_verificacion, text="Código FALCON").pack(anchor="w")
entrada_codigo_verificar = tk.Entry(frame_verificacion, width=35)
entrada_codigo_verificar.pack(anchor="w", pady=5)

tk.Button(
    frame_verificacion,
    text="Verificar archivo seleccionado",
    command=verificar_documento,
    
).pack(anchor="w", pady=5)
tk.Button(
    frame_verificacion,
    text="Descifrar documento",
    command=descifrar_documento,
).pack(anchor="w", pady=5)

# Administración
frame_admin = tk.LabelFrame(frame_main, text="Administración y seguridad", padx=10, pady=10)


boton_crear_usuario = tk.Button(frame_admin, text="Crear usuario", command=crear_usuario_gui)
boton_rotar_clave = tk.Button(frame_admin, text="Rotar clave", command=rotar_clave)
boton_revocar_clave = tk.Button(frame_admin, text="Revocar clave", command=revocar_clave)
boton_revocar_documento = tk.Button(frame_admin, text="Revocar documento", command=revocar_documento)
boton_ver_auditoria = tk.Button(frame_admin, text="Ver auditoría", command=ver_auditoria)

etiqueta_estado = tk.Label(frame_main, text="Estado: listo", font=("Arial", 10, "bold"))
etiqueta_estado.pack(pady=15)


# ============================================================
# ARRANQUE DEL PROGRAMA
# ============================================================

inicializar_db()

if sistema_requiere_configuracion():
    if not configuracion_inicial():
        root.destroy()
        raise SystemExit
    root.deiconify()

root.mainloop()
