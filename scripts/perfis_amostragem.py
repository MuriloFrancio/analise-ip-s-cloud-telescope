
"""Seleciona IPs por amostragem de volume."""

import collections
import csv
import hashlib
import json
import random
import sqlite3

from perfis_banco import FAIXAS, VERSAO, conectar_saida, faixa

# Sorteia as cotas das três faixas sem repetir IPs e grava a amostra fixa.
def selecionar(args):
    if not args.banco.is_file():
        raise ValueError(f"Banco de auditoria nao encontrado: {args.banco}")
    out = conectar_saida(args.saida)
    try:
        if out.execute("SELECT COUNT(*) FROM amostra").fetchone()[0]:
            raise ValueError("Esta pasta ja possui amostra. Para outra amostra, use nova --saida.")
        tamanhos = {"baixa":args.baixa, "media":args.media, "alta":args.alta}
        # A semente torna o sorteio repetível
        rng = random.Random(args.semente)
        reservas = {f:[] for f in FAIXAS}
        vistos = collections.Counter()
        audit = sqlite3.connect(args.banco.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            # Ordenacao estavel.
            for ip,n in audit.execute("SELECT ip_origem,pacotes FROM origens ORDER BY ip_origem"):
                f = faixa(n)
                vistos[f] += 1
                k = tamanhos[f]
                if k <= 0:
                    continue
                if len(reservas[f]) < k:
                    reservas[f].append((ip,int(n)))
                else:
                    j = rng.randrange(vistos[f])
                    if j < k:
                        reservas[f][j] = (ip,int(n))
        finally:
            audit.close()
        with sqlite3.connect(args.banco.resolve().as_uri() + '?mode=ro', uri=True) as audit:
            n_ok = audit.execute("SELECT COUNT(*) FROM arquivos WHERE status='ok'").fetchone()[0]
            n_erro = audit.execute("SELECT COUNT(*) FROM arquivos WHERE status='erro'").fetchone()[0]
        # Depois do sorteio, grava a seleção em uma ordem fixa.
        amostra = sorted((ip,f,n) for f in FAIXAS for ip,n in reservas[f])
        if not amostra:
            raise ValueError("A amostra ficou vazia. Confira os parametros de selecao.")
        params = {"versao":VERSAO,"semente":args.semente,"baixos":args.baixa,
                  "medios":args.media,"altos":args.alta,
                  "banco_original":str(args.banco.resolve()),
                  "pcaps_ok_na_selecao":n_ok,"pcaps_com_erro_na_selecao":n_erro,
                  "contagens_faixas_auditoria":dict(vistos)}
        hash_amostra=hashlib.sha256(json.dumps(amostra,ensure_ascii=False).encode()).hexdigest()
        params["hash_amostra"]=hash_amostra
        with out:
            out.executemany("INSERT INTO amostra(ip,faixa,pacotes_auditoria) VALUES(?,?,?)",amostra)
            out.execute("INSERT INTO parametros(chave,valor) VALUES('selecionar',?)",(json.dumps(params,ensure_ascii=False),))
        with (args.saida / "ips_selecionados.csv").open("w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f);w.writerow(("ip_origem","faixa_amostragem","pacotes_no_dataset_inteiro"))
            w.writerows(amostra)
        (args.saida / "amostra_info.json").write_text(json.dumps(params,indent=2,ensure_ascii=False),encoding="utf-8")
        print(f"PCAPs registrados na auditoria: {n_ok} OK, {n_erro} com erro")
        print("ATENCAO: a amostra representa somente os PCAPs processados ate agora.")
        print("IPs disponíveis por faixa:",dict(vistos))
        print("IPs selecionados:",dict(collections.Counter(f for _,f,_ in amostra)))
        print("Lista salva em:",args.saida / "ips_selecionados.csv")
    finally:
        out.close()
