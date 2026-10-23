"""Persistência das métricas no SQLite (tabelas definidas em sql/schema.sql)."""

import sqlite3
from pathlib import Path


FIELDS = (
    "total", "tcp", "udp", "icmp", "ipv4", "ipv6",
    "syn", "synack", "rst", "rstack", "echo_reply", "icmp_erro",
)


# Abre ou cria o SQLite e inicializa as tabelas a partir do schema.sql.
def conectar(caminho):
    """Cria o SQLite, se necessário, e garante as tabelas do schema.sql."""
    caminho = Path(caminho)
    schema = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"
    sql = schema.read_text(encoding="utf-8")

    caminho.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(caminho, timeout=120)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA busy_timeout=120000")
    con.execute("PRAGMA cache_size=-32000")
    try:
        con.executescript(sql)
    except Exception:
        con.close()
        raise
    return con


# Acumula contagens no SQLite sem sobrescrever os valores já existentes.
def incrementar(con, tabela, campos_chave, dados, contagens):
    """Acrescenta valores às agregações existentes no SQLite."""
    chaves = list(campos_chave)
    vals = chaves + list(contagens)
    placeholders = ",".join("?" for _ in vals)
    atualizacoes = ",".join(f"{x}={tabela}.{x}+excluded.{x}" for x in contagens)
    sql = (f"INSERT INTO {tabela} ({','.join(vals)}) VALUES ({placeholders}) "
           f"ON CONFLICT({','.join(chaves)}) DO UPDATE SET {atualizacoes}")
    rows = []
    for key, c in dados.items():
        ch = (key,) if not isinstance(key, tuple) else key
        rows.append((*ch, *(c if isinstance(c, (tuple, list)) else (c,))))
    if rows:
        con.executemany(sql, rows)


# Grava os resultados do PCAP em uma transação, evitando dados pela metade.
def salvar(con, nome, regiao, zona, data_nome, hora_nome, infos, duracao):
    """Grava os resultados de um PCAP em uma única transação."""
    (res, hourly, dest, resp, flags, icmp, origens, exemplos, primeiro, ultimo) = infos
    with con:
        con.execute("""INSERT INTO arquivos (
            arquivo,status,regiao,zona,data_nome,hora_nome,pacotes,tcp,udp,icmp,ipv4,ipv6,
            syn,synack,rst,rstack,echo_reply,icmp_erro,primeiro_ts,ultimo_ts,duracao_s,erro)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
            (nome, "ok", regiao, zona, data_nome, hora_nome, *res, primeiro, ultimo, duracao))
        incrementar(con, "por_hora", ("hora_epoch","regiao"),
                    {(h,regiao): vals for h, vals in hourly.items()}, FIELDS)
        incrementar(con, "portas_destino", ("dia","protocolo","porta"),
                    dest, ("pacotes","syn"))
        incrementar(con, "portas_origem_respostas", ("dia","porta"),
                    resp, ("synack","rst"))
        incrementar(con, "flags_tcp", ("flags",), flags, ("pacotes",))
        incrementar(con, "icmp_tipos", ("versao","tipo","codigo"), icmp, ("pacotes",))
        con.executemany("INSERT INTO exemplos VALUES (?,?,?,?,?,?,?,?,?,?)", exemplos)
        if origens:
            con.executemany("""INSERT INTO origens
                (ip_origem,pacotes,syn,synack,rst,mascara_regioes,arquivos_distintos,
                 max_portas_destino_distintas_em_arquivo,soma_portas_destino_distintas_por_arquivo,
                 primeira_observacao,ultima_observacao)
                VALUES (?,?,?,?,?,?,1,?,?,?,?)
                ON CONFLICT(ip_origem) DO UPDATE SET
                pacotes=origens.pacotes+excluded.pacotes,
                syn=origens.syn+excluded.syn,
                synack=origens.synack+excluded.synack,
                rst=origens.rst+excluded.rst,
                mascara_regioes=origens.mascara_regioes | excluded.mascara_regioes,
                arquivos_distintos=origens.arquivos_distintos+1,
                max_portas_destino_distintas_em_arquivo=MAX(origens.max_portas_destino_distintas_em_arquivo,excluded.max_portas_destino_distintas_em_arquivo),
                soma_portas_destino_distintas_por_arquivo=origens.soma_portas_destino_distintas_por_arquivo+excluded.soma_portas_destino_distintas_por_arquivo,
                primeira_observacao=MIN(origens.primeira_observacao,excluded.primeira_observacao),
                ultima_observacao=MAX(origens.ultima_observacao,excluded.ultima_observacao)
            """, [(ip, *val[:5],len(val[5]),len(val[5]),val[6],val[7]) for ip, val in origens.items()])
