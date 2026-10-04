"""Lógica de segurança em Python puro."""
import hashlib
import itertools
import os
import string
import time

ALFABETO = string.ascii_lowercase


def cesar(texto, deslocamento, decodificar=False):
    if decodificar:
        deslocamento = -deslocamento
    resultado = ""
    for letra in texto:
        if letra.lower() in ALFABETO:
            base = ord("A") if letra.isupper() else ord("a")
            resultado += chr((ord(letra) - base + deslocamento) % 26 + base)
        else:
            resultado += letra
    return resultado


def chave_valida(chave):
    chave = chave.lower()
    return len(chave) == 26 and set(chave) == set(ALFABETO)


def substituicao(texto, chave, decodificar=False):
    chave = chave.lower()
    origem, destino = (chave, ALFABETO) if decodificar else (ALFABETO, chave)
    tabela = str.maketrans(origem + origem.upper(), destino + destino.upper())
    return texto.translate(tabela)


def hash_simples(texto):
    return hashlib.sha256(texto.encode()).hexdigest()


def hash_com_sal(senha, sal=None):
    sal = sal or os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(sal), 200_000)
    return sal, h.hex()


CONJUNTOS = {
    "digitos": string.digits,
    "minusculas": string.ascii_lowercase,
    "minusculas_digitos": string.ascii_lowercase + string.digits,
}


def forca_bruta(hash_alvo, conjunto, tamanho_max=4, limite=2_000_000):
    caracteres = CONJUNTOS[conjunto]
    inicio = time.perf_counter()
    tentativas = 0
    for tamanho in range(1, tamanho_max + 1):
        for combinacao in itertools.product(caracteres, repeat=tamanho):
            tentativas += 1
            palpite = "".join(combinacao)
            if hash_simples(palpite) == hash_alvo:
                return resultado(True, palpite, tentativas, inicio, len(caracteres))
            if tentativas >= limite:
                return resultado(False, None, tentativas, inicio, len(caracteres))
    return resultado(False, None, tentativas, inicio, len(caracteres))


def resultado(achou, senha, tentativas, inicio, tam_conjunto):
    segundos = max(time.perf_counter() - inicio, 1e-6)
    taxa = tentativas / segundos
    return {
        "achou": achou,
        "senha": senha,
        "tentativas": tentativas,
        "segundos": round(segundos, 3),
        "tentativas_por_segundo": int(taxa),
        "estimativas": {n: formatar_tempo(tam_conjunto ** n / taxa) for n in (6, 8, 10, 12)},
    }


def formatar_tempo(s):
    if s < 60: return f"{s:.1f} segundos"
    if s < 3600: return f"{s / 60:.1f} minutos"
    if s < 86400: return f"{s / 3600:.1f} horas"
    if s < 86400 * 365: return f"{s / 86400:.1f} dias"
    return f"{s / (86400 * 365):,.0f} anos".replace(",", ".")


def avaliar_senha(senha):
    problemas = []
    if len(senha) < 12: problemas.append("Use pelo menos 12 caracteres.")
    if not any(c.islower() for c in senha): problemas.append("Falta letra minúscula.")
    if not any(c.isupper() for c in senha): problemas.append("Falta letra maiúscula.")
    if not any(c.isdigit() for c in senha): problemas.append("Falta número.")
    if not any(c in string.punctuation for c in senha): problemas.append("Falta símbolo.")
    if senha.lower() in {"123456", "senha", "password", "qwerty", "123456789", "admin"}:
        problemas.append("Está na lista das senhas mais usadas do mundo.")
    return max(5 - len(problemas), 0), problemas
