from flask import Flask, render_template, request
import sqlite3
import random
import math

app = Flask(__name__)

# ---------- DATABASE ----------
def init_db():
    conn = sqlite3.connect("mahasiswa.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS mahasiswa (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT,
            nim TEXT,
            jk TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

# ---------- ZIGZAG CIPHER ----------
def encrypt_rail_fence(text, key):
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0

    for char in text:
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        rail[row][col] = char
        col += 1
        row += 1 if dir_down else -1

    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return "".join(result)

def decrypt_rail_fence(cipher, key):
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    dir_down = None
    row, col = 0, 0

    for _ in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row += 1 if dir_down else -1

    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1

    result = []
    row, col = 0, 0
    for _ in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        row += 1 if dir_down else -1
    return "".join(result)

# ---------- VIGENERE CIPHER ----------
def vigenere_encrypt(plain_text, key):
    key = key.upper()
    plain_text = plain_text.upper()
    cipher_text = ""
    key_index = 0
    for char in plain_text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            cipher_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            key_index += 1
        else:
            cipher_text += char
    return cipher_text

def vigenere_decrypt(cipher_text, key):
    key = key.upper()
    cipher_text = cipher_text.upper()
    plain_text = ""
    key_index = 0
    for char in cipher_text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            plain_text += chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            key_index += 1
        else:
            plain_text += char
    return plain_text

# ---------- RSA IMPLEMENTATION ----------
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2, x1 = x1, x
        d, y1 = y1, y

    if temp_phi == 1:
        return d + phi

def generate_keypair(p, q):
    n = p * q
    phi = (p-1) * (q-1)

    # pilih e
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    return [pow(ord(char), e, n) for char in plaintext]

def decrypt(private_key, ciphertext):
    d, n = private_key
    return "".join([chr(pow(char, d, n)) for char in ciphertext])

# ---------- ROUTES ----------
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/zigzag", methods=["GET", "POST"])
def zigzag():
    result, error = None, None

    if request.method == "POST":
        mode = request.form["mode"]
        password = request.form["password"]
        rail = int(request.form["rail"])

        try:
            if mode == "encrypt":
                nama = request.form["nama"]
                nim = request.form["nim"]
                jk = request.form["jk"]

                cipher = encrypt_rail_fence(password, rail)

                # Simpan ke DB
                conn = sqlite3.connect("mahasiswa.db")
                c = conn.cursor()
                c.execute("INSERT INTO mahasiswa (nama, nim, jk, password) VALUES (?, ?, ?, ?)",
                          (nama, nim, jk, cipher))
                conn.commit()
                conn.close()

                result = cipher

            elif mode == "decrypt":
                result = decrypt_rail_fence(password, rail)

        except Exception as e:
            error = str(e)

    # Ambil semua data mahasiswa
    conn = sqlite3.connect("mahasiswa.db")
    c = conn.cursor()
    c.execute("SELECT * FROM mahasiswa")
    mahasiswa_list = c.fetchall()
    conn.close()

    return render_template("zigzag.html", result=result, error=error, mahasiswa=mahasiswa_list)

@app.route("/vigenere", methods=["GET", "POST"])
def vigenere():
    result, error = None, None

    if request.method == "POST":
        mode = request.form["mode"]
        password = request.form["password"]  # teks input
        key = request.form["key"]           # kunci Vigenere

        try:
            if mode == "encrypt":
                nama = request.form["nama"]
                nim = request.form["nim"]
                jk = request.form["jk"]

                cipher = vigenere_encrypt(password, key)

                conn = sqlite3.connect("mahasiswa.db")
                c = conn.cursor()
                c.execute("INSERT INTO mahasiswa (nama, nim, jk, password) VALUES (?, ?, ?, ?)",
                          (nama, nim, jk, cipher))
                conn.commit()
                conn.close()

                result = cipher

            elif mode == "decrypt":
                result = vigenere_decrypt(password, key)

        except Exception as e:
            error = str(e)

    conn = sqlite3.connect("mahasiswa.db")
    c = conn.cursor()
    c.execute("SELECT * FROM mahasiswa")
    mahasiswa_list = c.fetchall()
    conn.close()

    return render_template("vigenere.html", result=result, error=error, mahasiswa=mahasiswa_list)

@app.route("/rsa", methods=["GET", "POST"])
def rsa():
    result, error = None, None

    # generate key setiap kali load (untuk demo)
    public, private = generate_keypair(17, 19)  # contoh bilangan prima kecil

    if request.method == "POST":
        mode = request.form["mode"]
        password = request.form["password"]

        try:
            if mode == "encrypt":
                nama = request.form["nama"]
                nim = request.form["nim"]
                jk = request.form["jk"]

                cipher = encrypt(public, password)

                # Simpan ke DB (cipher jadi string biar gampang)
                conn = sqlite3.connect("mahasiswa.db")
                c = conn.cursor()
                c.execute("INSERT INTO mahasiswa (nama, nim, jk, password) VALUES (?, ?, ?, ?)",
                          (nama, nim, jk, str(cipher)))
                conn.commit()
                conn.close()

                result = cipher

            elif mode == "decrypt":
                # input password = cipher list string (contoh: [123,456,...])
                cipher_list = eval(password)
                result = decrypt(private, cipher_list)

        except Exception as e:
            error = str(e)

    # Ambil semua data mahasiswa
    conn = sqlite3.connect("mahasiswa.db")
    c = conn.cursor()
    c.execute("SELECT * FROM mahasiswa")
    mahasiswa_list = c.fetchall()
    conn.close()

    return render_template("rsa.html", result=result, error=error, mahasiswa=mahasiswa_list)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)