
"""Reconstrói históricos diários dos IPs selecionados a partir dos PCAPs."""

import collections
import gzip
import json
import sqlite3
import sys
import time
import zipfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import pyzipper
except ImportError:
    pyzipper = None

from capturas import metadados, iterar_pcap, ler_campos
from perfis_banco import conectar_saida, compactar, descompactar

# Este objeto guarda os contadores temporários de um IP em um dia.
@dataclass(slots=True)
class Dia:
    total:int=0
    tcp:int=0
    udp:int=0
    icmp:int=0
    syn:int=0
    synack:int=0
    rst:int=0
    mask:int=0
    tcpbits:int=0
    udpbits:int=0
    primeiro:float=float('inf')
    ultimo:float=float('-inf')

    def adicionar(self, ts, proto, flags, porta, bit_regiao):
        self.total += 1
        self.mask |= bit_regiao
        if ts < self.primeiro: self.primeiro=ts
        if ts > self.ultimo: self.ultimo=ts
        if proto == 6:
            self.tcp += 1
            if flags & 2 and not flags & 16: self.syn += 1
            if flags & 18 == 18: self.synack += 1
            if flags & 4: self.rst += 1
            if porta >= 0: self.tcpbits |= 1 << porta
        elif proto == 17:
            self.udp += 1
            if porta >= 0: self.udpbits |= 1 << porta
        elif proto in (1,58):
            self.icmp += 1

# Soma os dados de um PCAP ao histórico já acumulado de cada IP/dia.
def salvar_pcap(con, info, agregados, n):
    sql_get=("SELECT total,tcp,udp,icmp,syn,synack,rst,regiao_mask,tcp_portas,udp_portas,"
             "primeiro_ts,ultimo_ts FROM ip_dia WHERE ip=? AND dia=?")
    sql_insert=("INSERT INTO ip_dia(ip,dia,total,tcp,udp,icmp,syn,synack,rst,regiao_mask,"
                "tcp_portas,udp_portas,primeiro_ts,ultimo_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    sql_update=("UPDATE ip_dia SET total=?,tcp=?,udp=?,icmp=?,syn=?,synack=?,rst=?,"
                "regiao_mask=?,tcp_portas=?,udp_portas=?,primeiro_ts=?,ultimo_ts=? "
                "WHERE ip=? AND dia=?")
    with con:
        for (ip,dia), a in agregados.items():
            ant=con.execute(sql_get,(ip,dia)).fetchone()
            nums=(a.total,a.tcp,a.udp,a.icmp,a.syn,a.synack,a.rst)
            if ant is None:
                con.execute(sql_insert,(ip,dia,*nums,a.mask,compactar(a.tcpbits),
                                        compactar(a.udpbits),a.primeiro,a.ultimo))
            else:
                novos=tuple(ant[i]+nums[i] for i in range(7))
                con.execute(sql_update,(*novos,ant[7]|a.mask,
                                        compactar(descompactar(ant[8])|a.tcpbits),
                                        compactar(descompactar(ant[9])|a.udpbits),
                                        min(ant[10],a.primeiro),max(ant[11],a.ultimo),ip,dia))
        con.execute("INSERT OR REPLACE INTO processados(arquivo,status,pacotes_selecionados,mensagem) VALUES(?, 'ok', ?,NULL)",
                    (info.filename,n))

# Relê as capturas e guarda o comportamento diário só dos IPs selecionados.
def historico(args):
    if not args.zip.is_file():
        raise ValueError(f"ZIP nao encontrado: {args.zip}")
    con=conectar_saida(args.saida)
    try:
        # Um conjunto permite identificar rapidamente se o IP pertence à amostra.
        selecionados={r[0] for r in con.execute("SELECT ip FROM amostra")}
        if not selecionados:
            raise ValueError("Primeiro execute --fase selecionar com o banco de auditoria.")
        # Nao misturar ZIPs diferentes na mesma pasta.
        st=args.zip.stat()
        assinatura=json.dumps({"path":str(args.zip.resolve()),"bytes":st.st_size,
                               "mtime_ns":st.st_mtime_ns})
        assinatura_anterior=con.execute("SELECT valor FROM parametros WHERE chave='zip'").fetchone()
        if assinatura_anterior and assinatura_anterior[0] != assinatura:
            raise ValueError("O ZIP foi alterado. Use outra pasta --saida.")
        modo = 'auditados' if args.somente_auditados else 'todos'
        modo_anterior=con.execute("SELECT valor FROM parametros WHERE chave='modo_arquivos'").fetchone()
        if modo_anterior and modo_anterior[0] != modo:
            raise ValueError('O modo --somente-auditados mudou. Use outra pasta --saida.')
        with con:
            con.execute("INSERT OR IGNORE INTO parametros VALUES('zip',?)",(assinatura,))
            con.execute("INSERT OR IGNORE INTO parametros VALUES('modo_arquivos',?)",(modo,))
        cls=pyzipper.AESZipFile if pyzipper else zipfile.ZipFile
        if pyzipper is None:
            print("AVISO: pyzipper nao instalado (necessario para ZIP AES).")
        with cls(args.zip,'r',allowZip64=True) as z:
            arquivos=[x for x in z.infolist() if not x.is_dir() and x.filename.lower().endswith(('.pcap','.pcap.gz'))]
            # Teste coerente: reler somente PCAPs concluidos na auditoria anterior.
            if args.somente_auditados:
                if not args.banco.is_file():
                    raise ValueError(f"Banco da auditoria nao encontrado: {args.banco}")
                with sqlite3.connect(args.banco.resolve().as_uri() + "?mode=ro", uri=True) as auditoria:
                    nomes_auditados = {
                        r[0] for r in auditoria.execute(
                            "SELECT arquivo FROM arquivos WHERE status='ok'"
                        )
                    }
                arquivos = [item for item in arquivos if item.filename in nomes_auditados]
                if not arquivos:
                    raise ValueError("Nenhum PCAP concluido da auditoria foi encontrado no ZIP.")
            arquivos.sort(key=lambda x:(metadados(x.filename)[2],metadados(x.filename)[0],x.filename))
            regioes=sorted({metadados(x.filename)[0] for x in arquivos})
            if len(regioes)>60: raise ValueError("Numero inesperado de regioes")
            bits_regioes={r:1<<i for i,r in enumerate(regioes)}
            map_old=con.execute("SELECT valor FROM parametros WHERE chave='regioes'").fetchone()
            if map_old and json.loads(map_old[0]) != regioes:
                raise ValueError("Regioes diferentes das usadas anteriormente. Use outra --saida.")
            with con:
                con.execute("INSERT OR IGNORE INTO parametros VALUES('regioes',?)",(json.dumps(regioes),))
            concluidos={r[0] for r in con.execute("SELECT arquivo FROM processados WHERE status='ok'")}
            restantes=[x for x in arquivos if x.filename not in concluidos]
            if args.limitar_arquivos and len(restantes) > args.limitar_arquivos:
                # Distribui o teste por meses e regioes, em vez de pegar
                # os primeiros PCAPs de outubro apenas.
                k=args.limitar_arquivos
                if k==1:
                    restantes=[restantes[len(restantes)//2]]
                else:
                    restantes=[restantes[round(j*(len(restantes)-1)/(k-1))] for j in range(k)]
            print(f"IPs selecionados: {len(selecionados):,} | PCAPs no ZIP: {len(arquivos):,} | ja concluidos: {len(concluidos):,} | novos: {len(restantes):,}",flush=True)
            inicio=time.monotonic(); n_lidos=0
            for i,info in enumerate(restantes,1):
                bit_regiao=bits_regioes[metadados(info.filename)[0]]
                agg={}; capturados=0; cache_dias={}
                try:
                    with z.open(info,pwd=args.senha.encode('utf-8')) as bruto:
                        fonte=gzip.GzipFile(fileobj=bruto,mode='rb') if info.filename.lower().endswith('.gz') else bruto
                        with closing(fonte):
                            for ts,linktype,bytes_pacote in iterar_pcap(fonte):
                                if not 0 <= ts < 4102444800: continue
                                proto,flags,tipo_icmp,codigo,srcport,dstport,versao,ip=ler_campos(bytes_pacote,linktype,True)
                                # Ignora IPs fora da amostra e economiza espaço no histórico.
                                if ip not in selecionados: continue
                                epoch_day=int(ts)//86400
                                dia=cache_dias.get(epoch_day)
                                if dia is None:
                                    dia=datetime.fromtimestamp(epoch_day*86400,timezone.utc).strftime('%Y-%m-%d')
                                    cache_dias[epoch_day]=dia
                                key=(ip,dia)
                                d=agg.get(key)
                                if d is None: d=agg[key]=Dia()
                                d.adicionar(ts,proto,flags,dstport,bit_regiao)
                                capturados+=1
                    salvar_pcap(con,info,agg,capturados)
                    n_lidos+=capturados
                except Exception as exc:
                    # Erro nao e dado como concluido; pode ser tentado novamente.
                    print(f"ERRO {info.filename}: {exc}",file=sys.stderr,flush=True)
                    with con:
                        con.execute("INSERT OR REPLACE INTO processados VALUES(?, 'erro', 0, ?)",
                                    (info.filename,str(exc)[:500]))
                    continue
                if i<=3 or i%args.relatorio_a_cada==0:
                    print(f"[{i}/{len(restantes)}] OK | pacotes de IPs selecionados: {capturados:,} | dias/IP neste PCAP: {len(agg):,} | {info.filename}",flush=True)
                if i%args.relatorio_a_cada==0:
                    velocidade=i/max(time.monotonic()-inicio,0.1)
                    print(f"  Progresso: {i:,}/{len(restantes):,} | {velocidade:.2f} arquivos/s | restante estimado: {(len(restantes)-i)/max(velocidade,0.001)/3600:.1f}h",flush=True)
        print(f"Concluido: {len(restantes):,} arquivos tentados nesta execucao. Execute --fase exportar para gerar CSVs.")
    finally:
        con.close()
