
"""
Clusterizacao exploratoria de origens Cloud Telescope
"""
import argparse
import csv
import json
from pathlib import Path
from collections import Counter, defaultdict
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, adjusted_rand_score


# Abre um CSV e devolve as linhas em forma de dicionários.
def readcsv(path):
    with open(path, newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


# Grava a tabela gerada pela análise em um novo CSV.
def writecsv(path, records, columns):
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        w.writeheader(); w.writerows(records)


# Calcula uma mediana; se não houver dados, retorna zero.
def median(vals):
    return float(np.median(np.asarray(vals, dtype=float))) if len(vals) else 0.0


# Dá um nome descritivo ao cluster usando as medianas observadas.
def nome_grupo(r):
    if r['mediana_fracao_synack_tcp'] >= 0.50:
        return 'Respostas SYN-ACK predominantes'
    if r['mediana_fracao_icmp'] >= 0.80:
        return 'Comunicacoes ICMP predominantes'
    if r['mediana_fracao_udp'] >= 0.80:
        return 'Comunicacoes UDP predominantes'
    if r['mediana_fracao_rst_tcp'] >= 0.40:
        return 'TCP com redefinicoes frequentes'
    if r['mediana_dias_observados'] >= 70:
        return 'Sondagem persistente e diversificada'
    if r['mediana_dias_observados'] <= 2:
        return 'Atividade curta ou escassa'
    return 'Sondagem recorrente moderada'


# Monta as características dos IPs, aplica K-Means e exporta grupos e gráficos.
def run(args):
    pasta = Path(args.entrada); saida = Path(args.saida); saida.mkdir(parents=True, exist_ok=True)
    ips = readcsv(pasta / 'resumo_ips.csv')
    diario = readcsv(pasta / 'historico_diario_ips.csv')
    mensal = readcsv(pasta / 'atividade_mensal_ips.csv')
    if not ips or not diario:
        raise SystemExit('Faltam registros nos CSVs de entrada.')
    datas = sorted({r['dia_utc'] for r in diario})
    # A janela vem dos dados observados, não de datas fixas.
    from datetime import date
    dt_ini = min(date.fromisoformat(d) for d in datas)
    dt_fim = max(date.fromisoformat(d) for d in datas)
    dias_periodo = (dt_fim - dt_ini).days + 1
    # Dez características resumem volume, frequência, portas, regiões e protocolos.
    nomes = [
        'log_media_pacotes_por_dia', 'fracao_dias_observados',
        'log_maior_intervalo', 'concentracao_no_dia_maximo',
        'log_portas_distintas', 'fracao_regioes_aws',
        'fracao_udp', 'fracao_icmp', 'fracao_rst_tcp', 'fracao_synack_tcp'
    ]
    if args.total_regioes < 1:
        raise ValueError("--total-regioes deve ser positivo")
    matriz = []
    registro = []
    for r in ips:
        total = int(r['pacotes_lidos_piloto']); dias = int(r['dias_observados']); tcp = int(r['tcp'])
        if total <= 0 or dias <= 0:
            raise ValueError('IP sem historico positivo: ' + r['ip'] +
                             '. Confira se a fase historico terminou para a mesma amostra.')
        portas_tcp = int(r['portas_tcp_distintas_todo_periodo'])
        portas_udp = int(r['portas_udp_distintas_todo_periodo'])
        gap = int(r['maior_intervalo_sem_observacao_dias'])
        v = [
            np.log1p(total / dias), dias/dias_periodo,
            np.log1p(gap), int(r['max_pacotes_em_um_dia'])/total,
            np.log1p(portas_tcp+portas_udp), int(r['regioes_distintas'])/args.total_regioes,
            int(r['udp'])/total, int(r['icmp'])/total,
            int(r['rst'])/max(1,tcp), int(r['synack'])/max(1,tcp)
        ]
        matriz.append(v)
        registro.append({**r,
            'media_pacotes_dia_observado_exata':round(total/dias,5),
            'concentracao_dia_mais_movimentado':round(v[3],6),
            'fracao_dias_observados':round(v[1],6),
            'fracao_udp':round(v[6],6),'fracao_icmp':round(v[7],6),
            'fracao_rst_tcp':round(v[8],6),'fracao_synack_tcp':round(v[9],6),
            'portas_tcp_udp_distintas':portas_tcp + portas_udp,
            # Soma dos dois protocolos, e nao conjunto unico numerico de portas
        })
    X = np.asarray(matriz,dtype=float)
    if not np.all(np.isfinite(X)):
        raise RuntimeError('Features com valores invalidos.')
    # Limita valores extremos de algumas características para reduzir sua influência.
    Xclip = X.copy()
    lim_clips={}
    for j in [0, 2, 4]:
        lo, hi = np.percentile(X[:,j], [1,99])
        Xclip[:,j] = np.clip(X[:,j],lo,hi)
        lim_clips[nomes[j]]=[float(lo),float(hi)]
    # Coloca as características em escalas comparáveis antes do K-Means.
    scaler = StandardScaler()
    Z = scaler.fit_transform(Xclip)
    # Em testes pequenos, nao avaliar mais grupos que perfis realmente distintos.
    max_k = min(9, len(Z) - 1, len(np.unique(Z, axis=0)))
    if max_k < 3:
        raise ValueError('A amostra possui menos de 3 perfis distintos; aumente a amostra.')
    # Compara K de 3 a 9 com Silhouette e estabilidade entre duas sementes.
    resultados_k=[]
    for k in range(3, max_k + 1):
        mdl=KMeans(n_clusters=k,n_init=25,random_state=42)
        lab=mdl.fit_predict(Z)
        diferentes=len(set(lab))
        metric=(silhouette_score(Z,lab,sample_size=min(2000,len(Z)),random_state=42)
                if 1 < diferentes < len(Z) else None)
        lab2=KMeans(n_clusters=k,n_init=25,random_state=123).fit_predict(Z)
        stab=adjusted_rand_score(lab,lab2)
        s=Counter(lab)
        resultados_k.append(dict(k=k,silhouette=round(metric,5) if metric is not None else '',estabilidade_ari=round(stab,5),menor_grupo=min(s.values()),maior_grupo=max(s.values())))
    k=args.grupos
    if k not in range(3, max_k + 1): raise SystemExit(f'--grupos deve estar entre 3 e {max_k} para esta amostra')
    # Esta é a clusterização final com o K definido em --grupos.
    modelo=KMeans(n_clusters=k,random_state=42,n_init=40)
    rotulo=modelo.fit_predict(Z)
    if len(set(rotulo)) != k:
        raise ValueError(f"A amostra só produziu {len(set(rotulo))} grupos distintos para k={k}. "+
                         "Amplie a amostra ou diminua --grupos.")
    resumo=[]
    for j in range(k):
        ind=np.where(rotulo==j)[0]
        sub=[registro[i] for i in ind]
        col=lambda f:np.array([float(r[f]) for r in sub])
        cl=Counter(r['faixa_amostragem'] for r in sub)
        res={
            'id_original':int(j),'quantidade_ips':len(sub),
            'baixa':cl.get('baixa',0),'media':cl.get('media',0),'alta':cl.get('alta',0),
            'mediana_pacotes_total':round(median(col('pacotes_lidos_piloto')),1),
            'mediana_pacotes_dia_ativo':round(median(col('media_pacotes_dia_observado_exata')),2),
            'mediana_dias_observados':round(median(col('dias_observados')),1),
            'mediana_maior_intervalo_dias':round(median(col('maior_intervalo_sem_observacao_dias')),1),
            'mediana_concentracao_dia_maximo':round(median(col('concentracao_dia_mais_movimentado')),3),
            'mediana_portas_tcp_udp_distintas':round(median(col('portas_tcp_udp_distintas')),1),
            'mediana_regioes_distintas':round(median(col('regioes_distintas')),1),
            'mediana_fracao_udp':round(median(col('fracao_udp')),3),
            'mediana_fracao_icmp':round(median(col('fracao_icmp')),3),
            'mediana_fracao_rst_tcp':round(median(col('fracao_rst_tcp')),3),
            'mediana_fracao_synack_tcp':round(median(col('fracao_synack_tcp')),3),
            'pct_ips_um_dia':round(100*sum(int(r['dias_observados'])==1 for r in sub)/len(sub),1),
            'pct_ips_30dias_ou_mais':round(100*sum(int(r['dias_observados'])>=30 for r in sub)/len(sub),1),
        }
        res['nome_preliminar']=nome_grupo(res)
        resumo.append(res)
    # ID de grupo ordenado por uma combinacao de criterios para nomes comparaveis entre execucoes
    # Ordena os rótulos G1–G7 por mediana de dias, não por gravidade.
    ordem=sorted(resumo,key=lambda r:(-r['mediana_dias_observados'], -r['quantidade_ips']))
    mapa={r['id_original']:i+1 for i,r in enumerate(ordem)}
    nomes_perfil={r['id_original']:r['nome_preliminar'] for r in ordem}
    for r in resumo:r['grupo']=mapa[r['id_original']]
    resumo=sorted(resumo,key=lambda r:r['grupo'])
    # Mede a distância ao centro do cluster para escolher IPs representativos.
    dist=np.linalg.norm(Z[:,None,:]-modelo.cluster_centers_[None,:,:],axis=2)
    for i,r in enumerate(registro):
        oid=int(rotulo[i]);r['grupo']=mapa[oid];r['perfil_exploratorio']=nomes_perfil[oid]
        r['distancia_ao_centroide']=round(float(dist[i,oid]),4)
    resumo_csv=saida/'resumo_clusters.csv'
    writecsv(resumo_csv,resumo,['grupo','nome_preliminar','quantidade_ips','baixa','media','alta',
        'mediana_pacotes_total','mediana_pacotes_dia_ativo','mediana_dias_observados',
        'mediana_maior_intervalo_dias','mediana_concentracao_dia_maximo',
        'mediana_portas_tcp_udp_distintas','mediana_regioes_distintas',
        'mediana_fracao_udp','mediana_fracao_icmp','mediana_fracao_rst_tcp','mediana_fracao_synack_tcp',
        'pct_ips_um_dia','pct_ips_30dias_ou_mais'])
    writecsv(saida/'ips_clusterizados.csv',registro,list(registro[0].keys()))
    writecsv(saida/'validacao_quantidade_grupos.csv',resultados_k,list(resultados_k[0].keys()))
    # Indicadores temporais adicionais para inspecionar retornos, episodios e concentracao mensal.
    from datetime import date
    dias_por_ip=defaultdict(list)
    pacotes_mes=defaultdict(lambda:Counter())
    for r in diario:
        dias_por_ip[r['ip']].append((date.fromisoformat(r['dia_utc']),int(r['pacotes'])))
    for r in mensal:
        pacotes_mes[r['ip']][r['mes_utc']]+=int(r['pacotes'])
    tempos=[]
    for r in registro:
        eventos=sorted(dias_por_ip[r['ip']]); d=[x[0] for x in eventos]
        intervalos=[(b-a).days-1 for a,b in zip(d,d[1:])]
        streak=1;maior_streak=1
        for a,b in zip(d,d[1:]):
            streak=streak+1 if (b-a).days==1 else 1
            maior_streak=max(maior_streak,streak)
        meses=pacotes_mes[r['ip']]
        total=int(r['pacotes_lidos_piloto'])
        tempos.append({'ip':r['ip'],'grupo':r['grupo'],'perfil_exploratorio':r['perfil_exploratorio'],
            'primeiro_dia_observado':str(d[0]),'ultimo_dia_observado':str(d[-1]),
            'dias_observados':len(d),'meses_com_observacoes':len(meses),
            'maior_sequencia_de_dias_consecutivos':maior_streak,
            'maior_intervalo_entre_observacoes_dias':max(intervalos or [0]),
            'intervalos_sem_observacao_30dias_ou_mais':sum(v>=30 for v in intervalos),
            'possui_intervalo_30dias_ou_mais':int(any(v>=30 for v in intervalos)),
            'fracao_pacotes_no_mes_mais_intenso':round(max(meses.values())/total,6)})
    writecsv(saida/'indicadores_temporais.csv',tempos,list(tempos[0].keys()))
    # Agregacao de hist por grupo: total de pacotes, IPs ativos e pacotes por protocolo a cada mes
    ip_grupo={r['ip']:r['grupo'] for r in registro}
    mes_agregado=defaultdict(lambda:Counter())
    for r in mensal:
        if r['ip'] not in ip_grupo:continue
        kk=(ip_grupo[r['ip']],r['mes_utc'])
        mes_agregado[kk]['ips_ativos']+=1
        for name in ['pacotes','tcp','udp','icmp','syn','synack','rst']:
            mes_agregado[kk][name]+=int(r[name])
    linhas_m=[]
    for (g,m),vals in sorted(mes_agregado.items()):
        linhas_m.append({'grupo':g,'perfil_exploratorio':next(q['nome_preliminar'] for q in resumo if q['grupo']==g),'mes':m,**dict(vals)})
    writecsv(saida/'atividade_mensal_clusters.csv',linhas_m,['grupo','perfil_exploratorio','mes','ips_ativos','pacotes','tcp','udp','icmp','syn','synack','rst'])
    # Representantes proximos ao centroide de cada grupo: exemplos, nao IPs mais maliciosos
    rep=[]
    for j in range(k):
        idx=np.where(rotulo==j)[0]
        for i in sorted(idx,key=lambda q:dist[q,j])[:3]:
            r=registro[i]
            rep.append({'grupo':r['grupo'],'nome':r['perfil_exploratorio'],'ip':r['ip'],
                        'pacotes':r['pacotes_lidos_piloto'],'dias_observados':r['dias_observados'],
                        'portas_distintas':r['portas_tcp_udp_distintas'],'regioes_distintas':r['regioes_distintas']})
    rep.sort(key=lambda r:r['grupo'])
    writecsv(saida/'exemplos_representativos.csv',rep,list(rep[0].keys()))

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams['axes.spines.top'] = False; plt.rcParams['axes.spines.right']=False
    # Diagrama 1 PCA: cores automaticas do ciclo do Matplotlib, nao atribui significados
    pc=PCA(n_components=2).fit(Z)
    coords=pc.transform(Z)
    fig,ax=plt.subplots(figsize=(10,6),layout='constrained')
    for g in sorted({r['grupo'] for r in registro}):
        ids=[i for i,r in enumerate(registro) if r['grupo']==g]
        ax.scatter(coords[ids,0],coords[ids,1],s=10,alpha=.45,label=f'G{g} ({len(ids)} IPs)')
    ax.set(xlabel=f'Componente 1 ({pc.explained_variance_ratio_[0]*100:.1f}% da variacao)',
           ylabel=f'Componente 2 ({pc.explained_variance_ratio_[1]*100:.1f}% da variacao)',
           title=f'Perfis observados — PCA de {len(registro)} IPs (K={k})')
    ax.legend(loc='best',fontsize=8,frameon=False,ncol=2)
    fig.savefig(saida/'grafico_perfis_pca.png',dpi=160);plt.close(fig)
    # Diagrama 2 atividade / diversidade entre grupos
    gnum=[r['grupo'] for r in resumo]
    lab=[f'G{i}' for i in gnum]
    fig,ax=plt.subplots(figsize=(9,5),layout='constrained')
    ax.bar(lab,[r['mediana_dias_observados'] for r in resumo])
    ax.set(title='Mediana de dias observados por perfil',ylabel='Dias com pacotes registrados',xlabel='Grupo')
    fig.savefig(saida/'grafico_dias_por_perfil.png',dpi=160);plt.close(fig)
    fig,ax=plt.subplots(figsize=(9,5),layout='constrained')
    ax.bar(lab,[r['mediana_portas_tcp_udp_distintas'] for r in resumo])
    ax.set(title='Mediana de portas TCP/UDP distintas por perfil',ylabel='Numero de portas distintas',xlabel='Grupo')
    fig.savefig(saida/'grafico_portas_por_perfil.png',dpi=160);plt.close(fig)
    # Exemplos de atividade diaria com pausas e persistencia; log10 para escala visivel
    from datetime import timedelta
    # Um representante por grupo, escolhido pelo centroide calculado.
    selecionados=[]
    grupos_escolhidos=set()
    for r in rep:
        if r['grupo'] not in grupos_escolhidos and r['ip'] in dias_por_ip:
            selecionados.append(r['ip'])
            grupos_escolhidos.add(r['grupo'])
        if len(selecionados)==3:
            break
    if selecionados:
        ord_dates=[dt_ini+timedelta(days=j) for j in range(dias_periodo)]
        fig,ax=plt.subplots(figsize=(11,5.5),layout='constrained')
        for ip in selecionados:
            v=dict(dias_por_ip[ip]); vals=[np.log10(1+v.get(d,0)) for d in ord_dates]
            ax.plot(ord_dates,vals,label=f'{ip} (G{ip_grupo[ip]})',linewidth=1.3)
        ax.set(title=f'Exemplos de comportamento diário ({len(selecionados)} origens da amostra)',
               xlabel='Data UTC',ylabel='log10(1 + pacotes observados/dia)')
        ax.legend(frameon=False,fontsize=9)
        fig.autofmt_xdate()
        fig.savefig(saida/'grafico_historico_exemplos.png',dpi=160);plt.close(fig)
    info={
        'ips':len(ips),'ips_por_faixa_entrada':dict(Counter(r['faixa_amostragem'] for r in ips)),
        'pacotes_de_ips_selecionados':sum(int(r['pacotes_lidos_piloto']) for r in ips),
        'dias_na_janela':dias_periodo,'inicio_dos_registros':str(dt_ini),'fim_dos_registros':str(dt_fim),
        'k_escolhido':k,'criterio_k':'Exploracao k=3..9 com silhouette, estabilidade de sementes e interpretabilidade. Escolha provisoria k=7.',
        'validacao_k':resultados_k,'nomes_features':nomes,
        'recortes_winsorizacao_log':lim_clips,
        'explicacao':'Padronizacao por StandardScaler, log1p para intensidade, gaps e portas; P1/P99 winsorizacao nas variaveis logaritmicas. KMeans n_init=40 seed=42.',
        'variancia_pca_2componentes':float(pc.explained_variance_ratio_.sum()),
        'total_regioes_referencia':args.total_regioes,
        'ressalvas':['Cluster nao classifica ataque, benignidade ou intencao.',
          'Amostra estratificada por volume: frequencias nao representam necessariamente todos os IPs do ZIP.',
          'Presenca/ausencia e observacional; dias sem pacotes podem decorrer de cobertura dos sensores.',
          'Soma de portas TCP e UDP conta pares protocolo-porta, nao portas unicas numericas.',
          'CSV mensal contem quantidades de portas distintas, nao qual porta foi acessada; identificar troca de portas especificas requer extracao dirigida.']
    }
    info['indicadores_temporais']={
      'ips_com_intervalo_30_dias_ou_mais':sum(r['possui_intervalo_30dias_ou_mais'] for r in tempos),
      'ips_observados_em_todos_os_dias_do_periodo':sum(r['dias_observados']==dias_periodo for r in tempos),
      'ips_observados_em_um_so_dia':sum(r['dias_observados']==1 for r in tempos)
    }
    with open(saida/'resumo_clusterizacao.json' ,'w',encoding='utf-8') as f:
        json.dump(info,f,indent=2,ensure_ascii=False)
    print('Clustering K=',k,'| silhouette=',next(x['silhouette'] for x in resultados_k if x['k']==k),'| ARI=', next(x['estabilidade_ari'] for x in resultados_k if x['k']==k))
    for r in resumo:
        print(f"G{r['grupo']}: {r['quantidade_ips']:4d} IPs | {r['nome_preliminar']} | dias med={r['mediana_dias_observados']} | portas med={r['mediana_portas_tcp_udp_distintas']}")
    print('Arquivos em:',saida.absolute())


# Recebe a pasta dos CSVs, K e número de regiões via terminal.
def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--entrada',default='piloto_perfis',help='Diretorio dos CSVs exportados no piloto')
    p.add_argument('--saida',default='clusterizacao_piloto',help='Diretorio de resultados')
    p.add_argument('--grupos',type=int,default=7,help='K de 3 a 9 (padrao 7)')
    p.add_argument('--total-regioes',type=int,default=26,help='Total de regiões AWS de referência usado nas features (padrão 26)')
    run(p.parse_args())
if __name__=='__main__':main()
