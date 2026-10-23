"""Exportação dos resultados agregados no SQLite para CSV e JSON."""

import csv
import json
from datetime import datetime, timezone

from banco import FIELDS

# Executa uma consulta e escreve as linhas em um CSV com cabeçalho.
def csv_query(con, caminho, sql, cabecalho, transform=None):
    """Exporta o resultado de uma consulta SQL para CSV."""
    with caminho.open("w", newline="", encoding="utf-8-sig") as f:
        wr = csv.writer(f)
        wr.writerow(cabecalho)
        for lin in con.execute(sql):
            wr.writerow(transform(lin) if transform else lin)


# Gera os CSVs gerais e o resumo JSON sem reler o ZIP.
def exportar(con, saida):
    """Gera CSVs e resumo_geral.json a partir do SQLite."""
    saida.mkdir(parents=True, exist_ok=True)
    campos = ("arquivo", "status", "regiao", "zona", "data_nome", "pacotes", "tcp", "udp", "icmp", "syn", "synack", "rst", "rstack", "echo_reply", "icmp_erro", "primeiro_ts", "ultimo_ts", "duracao_s", "erro")
    csv_query(con, saida / "resumo_por_arquivo.csv",
        "SELECT " + ",".join(campos) + " FROM arquivos ORDER BY data_nome,regiao,arquivo",
        campos)
    csv_query(con, saida / "contagens_hora_regiao.csv",
        "SELECT hora_epoch,regiao," + ",".join(FIELDS) + " FROM por_hora ORDER BY hora_epoch,regiao",
        ("hora_utc", "regiao", *FIELDS),
        transform=lambda r: (datetime.fromtimestamp(r[0]*3600, timezone.utc).strftime("%Y-%m-%dT%H:00:00Z"), *r[1:]))
    query_d = "SELECT substr(datetime(hora_epoch*3600,'unixepoch'),1,10) AS dia,regiao," + ",".join("SUM("+x+")" for x in FIELDS) + " FROM por_hora GROUP BY dia,regiao ORDER BY dia,regiao"
    csv_query(con, saida / "contagens_dia_regiao.csv", query_d, ("data_utc","regiao",*FIELDS))
    csv_query(con, saida / "portas_destino_dia.csv",
        "SELECT * FROM portas_destino ORDER BY dia,protocolo,pacotes DESC",
        ("data_utc","protocolo","porta_destino","pacotes","syn"))
    csv_query(con, saida / "respostas_tcp_porta_origem_dia.csv",
        "SELECT * FROM portas_origem_respostas ORDER BY dia,synack DESC",
        ("data_utc","porta_origem","synack","rst"))
    csv_query(con, saida / "flags_tcp.csv", "SELECT * FROM flags_tcp ORDER BY pacotes DESC",("flags_decimal","pacotes"))
    csv_query(con, saida / "tipos_icmp.csv", "SELECT * FROM icmp_tipos ORDER BY pacotes DESC",("ip_versao","icmp_tipo","icmp_codigo","pacotes"))
    csv_query(con, saida / "exemplos_respostas.csv", "SELECT * FROM exemplos LIMIT 100000", ("arquivo","timestamp_utc","regiao","protocolo","ip_origem","porta_origem","porta_destino","tcp_flags_decimal","icmp_tipo","icmp_codigo"))
    if con.execute("SELECT valor FROM meta WHERE chave='perfil_origens'").fetchone() == ("1",):
        csv_query(con, saida / "origens_mais_ativas.csv",
            "SELECT ip_origem,pacotes,syn,synack,rst,mascara_regioes,arquivos_distintos,max_portas_destino_distintas_em_arquivo,soma_portas_destino_distintas_por_arquivo,primeira_observacao,ultima_observacao FROM origens ORDER BY pacotes DESC LIMIT 5000",
            ("ip_origem","pacotes","syn","synack","rst","regioes_distintas","arquivos_distintos",
             "max_portas_distintas_em_um_arquivo","soma_portas_distintas_por_arquivo_nao_global",
             "primeiro_timestamp_unix","ultimo_timestamp_unix"),
            transform=lambda r:(*r[:5], int(r[5]).bit_count(),*r[6:]))
    total = con.execute("SELECT COALESCE(SUM(pacotes),0),COUNT(*) FROM arquivos WHERE status='ok'").fetchone()
    erro = con.execute("SELECT COUNT(*) FROM arquivos WHERE status='erro'").fetchone()[0]
    agregados = con.execute("SELECT COALESCE(SUM(tcp),0),COALESCE(SUM(udp),0),COALESCE(SUM(icmp),0),COALESCE(SUM(syn),0),COALESCE(SUM(synack),0),COALESCE(SUM(rst),0) FROM arquivos WHERE status='ok'").fetchone()
    resumo = {"arquivos_processados":total[1],"pacotes_lidos":total[0],"arquivos_com_erro":erro,
              "tcp":agregados[0],"udp":agregados[1],"icmp":agregados[2],
              "syn":agregados[3],"synack":agregados[4],"rst":agregados[5],
              "nota":"Contagens completas APENAS para arquivos com status ok. SYNACK/ICMP nao provam ataques; falta qualificar backscatter."}
    (saida / "resumo_geral.json").write_text(json.dumps(resumo,ensure_ascii=False,indent=2),encoding="utf-8")
    print(f"CSV/JSON atualizados em: {saida.resolve()}")
    print("Resumo:",json.dumps(resumo,ensure_ascii=False))
