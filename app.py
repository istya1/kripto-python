from flask import Flask, render_template, request
import sqlite3

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


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
