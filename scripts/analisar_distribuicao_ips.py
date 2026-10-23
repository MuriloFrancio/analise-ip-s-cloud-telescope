
""" 
IP.
"""

import argparse
import csv
import json
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Os percentis mostram como o volume de pacotes se distribui entre os IPs.
PERCENTIS = [25, 50, 75, 90, 95, 99, 99.9]
# Estas três faixas descrevem volume; não são os grupos G1–G7 do K-Means.
FAIXAS = [
    ("baixa", 1, 9),
    ("media", 10, 999),
    ("alta", 1000, None),
]

# Só formata valores grandes para facilitar a leitura do relatório.
def formatar_numero(n):
    return f"{n:,}".replace(",", ".")


# Converte timestamp Unix para uma data em UTC legível.
def data_utc(v):
    if v is None:
        return ""
    return datetime.fromtimestamp(float(v), tz=timezone.utc).isoformat(timespec="seconds")


# Escreve uma tabela simples em CSV.
def gravar_csv(caminho, cabecalho, linhas):
    with caminho.open("w", encoding="utf-8-sig", newline="") as arq:
        writer = csv.writer(arq)
        writer.writerow(cabecalho)
        writer.writerows(linhas)


# Consulta todos os IPs da auditoria e monta percentis, faixas e top origens.
def executar(banco, saida):
    banco = banco.expanduser().resolve()
    if not banco.is_file():
        raise FileNotFoundError(f"Banco não encontrado: {banco}")
    saida.mkdir(parents=True, exist_ok=True)

    # Leitura somente; impede alterações acidentais no banco da auditoria.
    con = sqlite3.connect(banco.as_uri() + "?mode=ro", uri=True, timeout=120)
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA temp_store=FILE")
        con.execute("PRAGMA cache_size=-16384")
        tabelas = {x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "origens" not in tabelas:
            raise RuntimeError("A tabela 'origens' não existe. Confira se a auditoria foi feita com --perfil-origens.")

        print("Consultando a tabela 'origens' (não é necessário ler o ZIP)...", flush=True)
        total_ips, pacotes_perfil, menor, maior = con.execute(
            "SELECT COUNT(*), COALESCE(SUM(pacotes), 0), MIN(pacotes), MAX(pacotes) FROM origens"
        ).fetchone()
        if total_ips == 0:
            raise RuntimeError("A tabela 'origens' está vazia.")

        faixas = [dict(faixa=nome, quantidade_ips=0, pacotes=0) for nome, _, _ in FAIXAS]
        rank_percentil = {p: math.ceil(total_ips * p / 100) for p in PERCENTIS}
        percentis = {}
        acumulado = 0
        print("Calculando distribuição e percentis exatos (pode levar alguns minutos)...", flush=True)
        # O GROUP BY é feito pelo SQLite; Python mantém só contadores pequenos.
        for volume, qtd_ips in con.execute(
            "SELECT pacotes, COUNT(*) FROM origens GROUP BY pacotes ORDER BY pacotes ASC"
        ):
            volume, qtd_ips = int(volume), int(qtd_ips)
            acumulado += qtd_ips
            for p in PERCENTIS:
                if p not in percentis and acumulado >= rank_percentil[p]:
                    percentis[p] = volume
            for i, (_, ini, fim) in enumerate(FAIXAS):
                if volume >= ini and (fim is None or volume <= fim):
                    faixas[i]["quantidade_ips"] += qtd_ips
                    faixas[i]["pacotes"] += volume * qtd_ips
                    break

        for item in faixas:
            item["pct_ips"] = round(100 * item["quantidade_ips"] / total_ips, 4)
            item["pct_pacotes"] = round(100 * item["pacotes"] / pacotes_perfil, 4) if pacotes_perfil else 0

        top = list(con.execute(
            "SELECT ip_origem, pacotes, syn, synack, rst, arquivos_distintos, "
            "primeira_observacao, ultima_observacao "
            "FROM origens ORDER BY pacotes DESC LIMIT 20"
        ))
        top_saida = [
            (ip, pacotes, syn, synack, rst, n_arquivos, data_utc(inicio), data_utc(fim))
            for ip, pacotes, syn, synack, rst, n_arquivos, inicio, fim in top
        ]
        gravar_csv(saida / "faixas_volume_observadas.csv",
                   ["faixa_pacotes_no_periodo", "quantidade_ips", "percentual_ips", "total_pacotes", "percentual_pacotes"],
                   [(f["faixa"], f["quantidade_ips"], f["pct_ips"], f["pacotes"], f["pct_pacotes"]) for f in faixas])
        gravar_csv(saida / "top_20_origens.csv",
                   ["ip_origem", "pacotes", "syn", "synack", "rst", "arquivos_distintos", "primeira_observacao_utc", "ultima_observacao_utc"], top_saida)

        info = {
            "banco": str(banco),
            "total_ips_distintos": total_ips,
            "pacotes_associados_a_ips_de_origem": pacotes_perfil,
            "menor_contagem_pacotes_ip": menor,
            "maior_contagem_pacotes_ip": maior,
            "percentis_volume_pacotes_por_ip": {str(p): percentis.get(p) for p in PERCENTIS},
            "faixas_descritivas": faixas,
            "nota": "Faixas de volume baixa/média/alta; não são os clusters G1–G7. "
                    "O total é acumulado em todo o período processado, incluindo março de 2024 se presente. "
                    "A tabela origens não fornece dias ativos nem o histórico diário de cada IP. "
                    "A soma pode diferir de pacotes_lidos por causa de pacotes sem IP de origem analisável."
        }
        (saida / "distribuicao_ips.json").write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"\nIPs distintos: {formatar_numero(total_ips)}")
        print(f"Pacotes vinculados a IPs: {formatar_numero(pacotes_perfil)}")
        print(f"Pacotes por IP: mínimo={formatar_numero(menor)} | máximo={formatar_numero(maior)}")
        print("\nPercentis (pacotes por IP no período):")
        for p in PERCENTIS:
            print(f"  P{p}: {formatar_numero(percentis[p])}")
        print("\nFaixa             IPs              % IPs      % pacotes")
        for f in faixas:
            print(f"{f['faixa']:<18}{formatar_numero(f['quantidade_ips']):>12}   {f['pct_ips']:>9.3f}%   {f['pct_pacotes']:>9.3f}%")
        print(f"\nArquivos em: {saida.resolve()}")
        print("  distribuicao_ips.json | faixas_volume_observadas.csv | top_20_origens.csv")
    finally:
        con.close()


# Recebe os caminhos informados no terminal e executa a análise.
def main():
    p = argparse.ArgumentParser(description="Distribuição de pacotes por IP de origem no banco da auditoria")
    p.add_argument("--banco", type=Path, default=Path("auditoria_integral/auditoria.sqlite"))
    p.add_argument("--saida", type=Path, default=Path("distribuicao_ips"))
    args = p.parse_args()
    try:
        executar(args.banco, args.saida)
    except (FileNotFoundError, RuntimeError, sqlite3.Error) as e:
        p.exit(1, f"Erro: {e}\n")

if __name__ == "__main__":
    main()
