from flask import Flask, jsonify, render_template, request
import seguranca as s

app = Flask(__name__)


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/cifrar")
def cifrar():
    d = request.get_json()
    decodificar = d.get("acao") == "decodificar"
    if d["metodo"] == "cesar":
        try:
            desloc = int(d.get("chave", 3))
        except ValueError:
            return jsonify(erro="O deslocamento precisa ser um número."), 400
        return jsonify(saida=s.cesar(d["texto"], desloc, decodificar))
    if not s.chave_valida(d.get("chave", "")):
        return jsonify(erro="A chave precisa ter as 26 letras do alfabeto, embaralhadas e sem repetir."), 400
    return jsonify(saida=s.substituicao(d["texto"], d["chave"], decodificar))


@app.post("/api/hash")
def hash_():
    senha = request.get_json().get("senha", "")
    sal1, h1 = s.hash_com_sal(senha)
    sal2, h2 = s.hash_com_sal(senha)
    return jsonify(
        sha256=s.hash_simples(senha),
        sha256_de_novo=s.hash_simples(senha),
        com_sal=[{"sal": sal1, "hash": h1}, {"sal": sal2, "hash": h2}],
    )


@app.post("/api/forca-bruta")
def forca_bruta():
    d = request.get_json()
    senha, conjunto = d.get("senha", ""), d.get("conjunto", "digitos")
    if not senha or len(senha) > 4:
        return jsonify(erro="Use uma senha de teste de 1 a 4 caracteres."), 400
    if conjunto not in s.CONJUNTOS or any(c not in s.CONJUNTOS[conjunto] for c in senha):
        return jsonify(erro="A senha tem caracteres fora do conjunto escolhido."), 400
    return jsonify(s.forca_bruta(s.hash_simples(senha), conjunto))


@app.post("/api/avaliar")
def avaliar():
    nota, problemas = s.avaliar_senha(request.get_json().get("senha", ""))
    return jsonify(nota=nota, problemas=problemas)


if __name__ == "__main__":
    app.run(debug=False)
