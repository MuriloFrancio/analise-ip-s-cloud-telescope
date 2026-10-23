
"""Exporta históricos e indicadores dos IPs em CSV/JSON."""

import collections
import csv
import json
from datetime import datetime

from perfis_banco import CAMPOS, conectar_saida, descompactar

# Transforma o perfis.sqlite em tabelas por IP, dia e mês; confere os totais.
def exportar(args):
    con=conectar_saida(args.saida)
    try:
        regioes_r=con.execute("SELECT valor FROM parametros WHERE chave='regioes'").fetchone()
        if not regioes_r:
            raise ValueError("Sem historico. Execute --fase historico primeiro.")
        regioes=json.loads(regioes_r[0]); agrupamentos=collections.defaultdict(list)
        dias_reg=collections.Counter(); meses={}
        hist_path=args.saida/'historico_diario_ips.csv'
        hist=hist_path.open('w',encoding='utf-8-sig',newline='')
        w=csv.writer(hist)
        w.writerow(("ip","faixa_amostragem","dia_utc","pacotes","tcp","udp","icmp","syn","synack","rst",
                    "regioes_distintas","portas_tcp_distintas","portas_udp_distintas"))
        resultados={}
        # Parte dos IPs selecionados, mesmo dos que não tiveram observação no histórico.
        for ip,faixa,pacotes_audit in con.execute("SELECT ip,faixa,pacotes_auditoria FROM amostra ORDER BY ip"):
            resultados[ip]={"faixa":faixa,"auditoria":pacotes_audit,"dias":0,"total":0,"tcp":0,"udp":0,"icmp":0,
                            "syn":0,"synack":0,"rst":0,"tcpbits":0,"udpbits":0,"mask":0,
                            "primeiro":None,"ultimo":None,"max_dia":0,"maior_lacuna":0,"dia_anterior":None}
        try:
            sql="SELECT ip,dia,total,tcp,udp,icmp,syn,synack,rst,regiao_mask,tcp_portas,udp_portas,primeiro_ts,ultimo_ts FROM ip_dia ORDER BY ip,dia"
            for r in con.execute(sql):
                ip,dia=r[0],r[1]; a=resultados[ip]
                tcpbits=descompactar(r[10]);udpbits=descompactar(r[11])
                a['dias']+=1
                for j,k in enumerate(CAMPOS,2):a[k]+=r[j]
                a['tcpbits'] |= tcpbits;a['udpbits'] |= udpbits;a['mask'] |= r[9]
                a['max_dia']=max(a['max_dia'],r[2]);a['primeiro']=min(a['primeiro'],r[12]) if a['primeiro'] is not None else r[12]
                a['ultimo']=max(a['ultimo'],r[13]) if a['ultimo'] is not None else r[13]
                ord_dia=datetime.strptime(dia,'%Y-%m-%d').date().toordinal()
                if a['dia_anterior'] is not None:
                    a['maior_lacuna']=max(a['maior_lacuna'],ord_dia-a['dia_anterior']-1)
                a['dia_anterior']=ord_dia
                w.writerow((ip,a['faixa'],dia,*r[2:9],r[9].bit_count(),tcpbits.bit_count(),udpbits.bit_count()))
                chave=(ip,dia[:7]);v=meses.get(chave)
                if v is None: v=meses[chave]=[0,0,0,0,0,0,0,0,0,0] # dias, total, tcp, udp, icmp, syn, synack, rst, tcpbits, udpbits
                v[0]+=1
                for i1,j1 in ((1,2),(2,3),(3,4),(4,5),(5,6),(6,7),(7,8)):
                    v[i1]+=r[j1]
                v[8]|=tcpbits;v[9]|=udpbits
        finally:
            hist.close()
        with (args.saida/'resumo_ips.csv').open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f)
            w.writerow(("ip","faixa_amostragem","pacotes_auditoria_todo_periodo","pacotes_lidos_piloto",
                        "dias_observados","media_pacotes_dia_observado","max_pacotes_em_um_dia",
                        "maior_intervalo_sem_observacao_dias","regioes_distintas","portas_tcp_distintas_todo_periodo",
                        "portas_udp_distintas_todo_periodo","tcp","udp","icmp","syn","synack","rst","primeiro_timestamp","ultimo_timestamp"))
            for ip,a in resultados.items():
                w.writerow((ip,a['faixa'],a['auditoria'],a['total'],a['dias'],
                            round(a['total']/a['dias'],2) if a['dias'] else 0,a['max_dia'],a['maior_lacuna'],
                            a['mask'].bit_count(),a['tcpbits'].bit_count(),a['udpbits'].bit_count(),
                            *(a[k] for k in CAMPOS[1:]),a['primeiro'],a['ultimo']))
        with (args.saida/'atividade_mensal_ips.csv').open('w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f)
            w.writerow(("ip","mes_utc","dias_observados","pacotes","tcp","udp","icmp","syn","synack","rst",
                        "portas_tcp_distintas_mes","portas_udp_distintas_mes"))
            for (ip,mes),v in sorted(meses.items()):
                w.writerow((ip,mes,*v[:8],v[8].bit_count(),v[9].bit_count()))
        n_zip=con.execute("SELECT COUNT(*) FROM processados WHERE status='ok'").fetchone()[0]
        # Compara os totais reconstruídos com a auditoria para achar divergências.
        verificacao=[]
        for ip, a in resultados.items():
            if a['auditoria'] != a['total']:
                verificacao.append(ip)
        modo_reg=con.execute("SELECT valor FROM parametros WHERE chave='modo_arquivos'").fetchone()
        resumo={"ips_amostrados":len(resultados),
                "somente_auditados": bool(modo_reg and modo_reg[0]=='auditados'),
                "ips_com_observacao":sum(x['dias']>0 for x in resultados.values()),
                "pcaps_processados_ok":n_zip,
                "ips_com_contagem_diferente_da_auditoria":len(verificacao),
                "nota_conferencia":"A comparacao so valida a consistencia com a auditoria usada na selecao. Nao prova cobertura do ZIP completo.",
                "pcaps_com_erro":con.execute("SELECT COUNT(*) FROM processados WHERE status='erro'").fetchone()[0],
                "pacotes_da_amostra":sum(x['total'] for x in resultados.values()),
                "ip_dias_observados":sum(x['dias'] for x in resultados.values()),
                "faixas_ips_com_observacao":dict(collections.Counter(x['faixa'] for x in resultados.values() if x['dias'])),
                "observacao":"Ausencia em um dia = nao observado pelos sensores processados, NAO prova inatividade do IP. Os totais da amostra original incluem marco. O maior intervalo trata dias entre observacoes e nao desconta interrupcoes de sensores."}
        (args.saida/'resumo_piloto.json').write_text(json.dumps(resumo,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(resumo,ensure_ascii=False,indent=2))
        print("Arquivos gerados:",hist_path.name,"resumo_ips.csv","atividade_mensal_ips.csv","resumo_piloto.json",sep=' | ')
    finally:
        con.close()
