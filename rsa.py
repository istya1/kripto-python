from flask import Flask, render_template, request
import sqlite3
import math
import random

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
