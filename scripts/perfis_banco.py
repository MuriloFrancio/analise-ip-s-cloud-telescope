
"""Estruturas SQLite e utilitários dos históricos de IPs."""

import sqlite3
import zlib
from pathlib import Path

VERSAO = 1
FAIXAS = ("baixa", "media", "alta")
CAMPOS = ("total", "tcp", "udp", "icmp", "syn", "synack", "rst")

# Define baixa, média ou alta atividade a partir do total de pacotes por IP.
def faixa(pacotes):
    if pacotes < 10:
        return "baixa"
    if pacotes < 1000:
        return "media"
    return "alta"

# Abre ou cria o perfis.sqlite com amostra e históricos por IP/dia.
def conectar_saida(saida):
    saida.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(saida / "perfis.sqlite", timeout=120)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA busy_timeout=120000")
    con.executescript("""
      CREATE TABLE IF NOT EXISTS parametros (chave TEXT PRIMARY KEY, valor TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS amostra (
          ip TEXT PRIMARY KEY, faixa TEXT NOT NULL, pacotes_auditoria INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS processados (
          arquivo TEXT PRIMARY KEY, status TEXT NOT NULL, pacotes_selecionados INTEGER,
          mensagem TEXT
      );
      CREATE TABLE IF NOT EXISTS ip_dia (
          ip TEXT NOT NULL, dia TEXT NOT NULL,
          total INTEGER NOT NULL, tcp INTEGER NOT NULL, udp INTEGER NOT NULL,
          icmp INTEGER NOT NULL, syn INTEGER NOT NULL, synack INTEGER NOT NULL,
          rst INTEGER NOT NULL, regiao_mask INTEGER NOT NULL,
          tcp_portas BLOB NOT NULL, udp_portas BLOB NOT NULL,
          primeiro_ts REAL NOT NULL, ultimo_ts REAL NOT NULL,
          PRIMARY KEY(ip,dia)
      );
    """)
    return con

# Comprime o conjunto de portas observado para economizar espaço no SQLite.
def compactar(bits):
    b = bits.to_bytes(max(1,(bits.bit_length()+7)//8),'little')
    return zlib.compress(b,level=1)

# Recupera o conjunto de portas que foi armazenado compactado.
def descompactar(blob):
    return int.from_bytes(zlib.decompress(blob),'little')
