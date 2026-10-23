
"""
Gráficos de perfis temporais da amostra Cloud Telescope.
"""
import argparse
import csv
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.dates import MonthLocator, DateFormatter

# Define a aparência padrão das figuras Matplotlib.
def style():
    plt.rcParams.update({
        'figure.figsize': (9.3, 5.0), 'figure.dpi': 145,
        'savefig.dpi': 165, 'font.size': 11,
        'axes.spines.top': False, 'axes.spines.right': False,
        'axes.grid': True, 'axes.axisbelow': True,
        'grid.alpha': 0.17, 'grid.linestyle': '--',
    })

# Ajusta espaçamentos, salva a figura e libera a memória.
def save(fig, dest):
    fig.tight_layout(pad=1.5)
    fig.savefig(dest, bbox_inches='tight', facecolor='white')
    plt.close(fig)

# Lê históricos e clusters para criar gráficos mensais e casos individuais.
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--entrada', type=Path, required=True)
    parser.add_argument('--clusters', type=Path, required=True)
    parser.add_argument('--saida', type=Path, required=True)
    parser.add_argument('--inicio-mes', default='2023-10', help='Primeiro mês no formato AAAA-MM')
    parser.add_argument('--fim-mes', default='2024-02', help='Último mês no formato AAAA-MM')
    parser.add_argument('--casos', nargs='*', default=None, help='IPs individuais; se omitido, usa representantes próximos aos centroides.')
    parser.add_argument('--grupos-foco', nargs='+', default=None, help='Filtrar grupos, ex: G1 G4')
    parser.add_argument('--ips-por-grupo', type=int, default=0, help='Selecionar N IPs representativos de cada grupo (0 = selecao padrao)')
    a=parser.parse_args()
    if a.ips_por_grupo < 0:
        parser.error('--ips-por-grupo precisa ser >= 0')
    months = pd.period_range(a.inicio_mes, a.fim_mes, freq='M')
    if len(months) == 0:
        parser.error('Período inválido: --inicio-mes precisa ser anterior ou igual a --fim-mes')
    month_labels = [f'{m.month:02d}/{str(m.year)[-2:]}' for m in months]
    dt_ini = months[0].to_timestamp()
    dt_fim_exclusivo = (months[-1] + 1).to_timestamp()
    a.saida.mkdir(parents=True,exist_ok=True)
    (a.saida/'por_grupo').mkdir(exist_ok=True)
    (a.saida/'casos_reais').mkdir(exist_ok=True)
    style()
    cl_all=pd.read_csv(a.clusters)
    if a.grupos_foco:
        try:
            filtro = {int(valor.upper().removeprefix('G')) for valor in a.grupos_foco}
        except ValueError:
            parser.error('Use grupos como G1 G4 ou 1 4')
        desconhecidos = filtro - set(cl_all['grupo'])
        if desconhecidos:
            parser.error(f'Grupos nao encontrados nos clusters: {sorted(desconhecidos)}')
        cl_all = cl_all[cl_all['grupo'].isin(filtro)].copy()
    cl=cl_all[['ip','grupo']].copy()
    nomes_grupo=(cl_all.groupby('grupo')['perfil_exploratorio'].first().to_dict()
                 if 'perfil_exploratorio' in cl_all.columns else {})
    def nome_grupo(g):
        return nomes_grupo.get(g, f'Grupo {g}')
    # Lê os CSVs mensais e diários; nenhum PCAP é reaberto aqui.
    mens=pd.read_csv(a.entrada/'atividade_mensal_ips.csv')
    dia=pd.read_csv(a.entrada/'historico_diario_ips.csv')
    mens['mes_utc']=pd.PeriodIndex(mens['mes_utc'],freq='M')
    mens=mens[mens['mes_utc'].isin(months)].merge(cl,on='ip',how='inner',validate='many_to_one')
    dia['dia_utc']=pd.to_datetime(dia['dia_utc'])
    dia=dia[(dia['dia_utc']>=dt_ini) & (dia['dia_utc']<dt_fim_exclusivo)]
    ips_per_group=cl.groupby('grupo')['ip'].nunique().to_dict()
    total=cl['ip'].nunique()
    if total == 0:
        raise SystemExit('Nenhum IP encontrado em --clusters.')
    assert not mens.duplicated(['ip','mes_utc']).any()
    mens['pacotes_por_dia_observado']=mens['pacotes']/mens['dias_observados'].where(mens['dias_observados']>0)

    # Calcula a atividade mensal de cada grupo para comparação.
    metrics=mens.groupby(['grupo','mes_utc'], observed=True).agg(
        ips_ativos=('ip','nunique'),
        pacotes_totais=('pacotes','sum'),
        mediana_pacotes_por_dia_observado=('pacotes_por_dia_observado','median'),
        media_pacotes_por_dia_observado=('pacotes_por_dia_observado','mean'),
        mediana_portas_tcp_distintas=('portas_tcp_distintas_mes','median'),
        mediana_portas_udp_distintas=('portas_udp_distintas_mes','median'),
    ).reset_index()
    metrics['ips_cluster']=metrics['grupo'].map(ips_per_group)
    metrics['pct_ips_ativos']=100*metrics['ips_ativos']/metrics['ips_cluster']
    metrics['mes_utc']=metrics['mes_utc'].astype(str)
    metrics.to_csv(a.saida/'indicadores_mensais_grupos.csv',index=False,float_format='%.3f')

    fig,ax=plt.subplots()
    for g in sorted(ips_per_group):
        tmp=metrics[metrics['grupo']==g].set_index('mes_utc').reindex(months.astype(str),fill_value=0)
        ax.plot(month_labels,tmp['pct_ips_ativos'],marker='o',linewidth=1.9,label=f'G{g} — {nome_grupo(g)}')
    ax.set(ylabel='IPs observados no mês (% do respectivo grupo)',
           title='Frequência mensal das origens por perfil')
    ax.set_ylim(bottom=0,top=105)
    ax.legend(fontsize=8.5,loc='upper center',bbox_to_anchor=(0.5,-0.19),ncol=2,frameon=False)
    save(fig,a.saida/'comparacao_ips_ativos_mensais.png')

    fig,ax=plt.subplots()
    for g in sorted(ips_per_group):
        tmp=metrics[metrics['grupo']==g].set_index('mes_utc').reindex(months.astype(str),fill_value=0)
        ax.plot(month_labels,tmp['mediana_pacotes_por_dia_observado'],marker='o',label=f'G{g}')
    ax.set(ylabel='Mediana de pacotes/dia observado por IP',title='Intensidade típica mensal por perfil')
    ax.set_yscale('symlog',linthresh=1)
    ax.legend(ncol=4,frameon=False)
    save(fig,a.saida/'comparacao_intensidade_mediana.png')

    for g in sorted(ips_per_group):
        tmp=metrics[metrics['grupo']==g].set_index('mes_utc').reindex(months.astype(str),fill_value=0)
        y=tmp['mediana_pacotes_por_dia_observado'].to_numpy()
        fig,ax=plt.subplots()
        ax.plot(month_labels,y,marker='o',linewidth=2.2)
        ax.fill_between(range(len(y)),y,alpha=.1)
        for k,val in enumerate(y):
            ax.annotate(f'{val:,.1f}'.replace(',','.'),(k,val),xytext=(0,9),textcoords='offset points',ha='center',fontsize=9)
        ylim = max(float(y.max())*1.24,1.8)
        ax.set_ylim(0,ylim)
        ax.set(ylabel='Mediana de pacotes por dia com observação',
               title=f'G{g} — {nome_grupo(g)}  |  {ips_per_group[g]:,} IPs'.replace(',','.'))
        ax.text(.01,-.17, 'Mediana entre IPs com pelo menos um pacote no respectivo mês.',transform=ax.transAxes,fontsize=9)
        save(fig,a.saida/'por_grupo'/f'G{g}_intensidade_mensal.png')

    # Casos de desaparecimento e reaparecimento. Zeros indicam ausência registrada no mês.
    case_rows=[]
    # Permite escolher IPs manualmente ou selecionar representantes por grupo.
    if a.casos is not None:
        casos = a.casos
    elif a.ips_por_grupo:
        ordem = ['grupo']
        if 'distancia_ao_centroide' in cl_all.columns:
            ordem.append('distancia_ao_centroide')
        ordem.append('ip')
        casos = (cl_all.sort_values(ordem)
                 .groupby('grupo', sort=True).head(a.ips_por_grupo)['ip'].tolist())
    else:
        if 'distancia_ao_centroide' in cl_all.columns:
            casos = (cl_all.sort_values('distancia_ao_centroide')
                     .drop_duplicates('grupo')['ip'].head(4).tolist())
        else:
            casos = cl.drop_duplicates('grupo')['ip'].head(4).tolist()
    for ip in casos:
        if ip not in set(cl['ip']):
            print(f'Aviso: IP {ip} não consta na amostra; ignorado.')
            continue
        g=int(cl.loc[cl.ip==ip,'grupo'].iloc[0])
        tmp=mens[mens.ip==ip].set_index('mes_utc').reindex(months)
        values=tmp[['pacotes','dias_observados','portas_tcp_distintas_mes','portas_udp_distintas_mes']].fillna(0)
        for mes,row in values.iterrows():
            case_rows.append({'ip':ip,'grupo':g,'mes_utc':str(mes),
                              'pacotes':int(row['pacotes']), 'dias_observados':int(row['dias_observados']),
                              'portas_tcp_distintas_mes':int(row['portas_tcp_distintas_mes']),
                              'portas_udp_distintas_mes':int(row['portas_udp_distintas_mes'])})
        fig,ax=plt.subplots()
        ax.bar(month_labels,values['pacotes'],width=.58)
        for k,v in enumerate(values['pacotes']):
            ax.annotate(f'{int(v):,}'.replace(',','.'),(k,v),textcoords='offset points',xytext=(0,8),ha='center',fontsize=9)
        ax.set(ylabel='Pacotes observados no mês',title=f'G{g} • {ip} — Volume mensal')
        ax.set_ylim(bottom=0,top=max(1,float(values['pacotes'].max())*1.2))
        save(fig,a.saida/'casos_reais'/f'{ip.replace(".","_")}_pacotes.png')

        fig,ax=plt.subplots()
        ax.bar(np.arange(len(months))-.18, values['portas_tcp_distintas_mes'],width=.36,label='TCP')
        ax.bar(np.arange(len(months))+.18, values['portas_udp_distintas_mes'],width=.36,label='UDP')
        ax.set_xticks(np.arange(len(months)), month_labels)
        ax.set(ylabel='Portas distintas no mês',title=f'G{g} • {ip} — Diversidade de portas')
        ax.set_ylim(bottom=0,top=max(2,float(values[['portas_tcp_distintas_mes','portas_udp_distintas_mes']].max().max())*1.22))
        ax.legend(frameon=False)
        save(fig,a.saida/'casos_reais'/f'{ip.replace(".","_")}_portas.png')

        z=dia[dia.ip==ip]
        fig,ax=plt.subplots(figsize=(11,4))
        ax.scatter(z['dia_utc'],z['pacotes'],s=26,alpha=.83)
        ax.set_yscale('symlog',linthresh=1)
        ax.set(ylabel='Pacotes nos dias com observação',title=f'G{g} • {ip} — Datas em que apareceu')
        ax.set_xlim(dt_ini,dt_fim_exclusivo)
        ax.xaxis.set_major_locator(MonthLocator())
        ax.xaxis.set_major_formatter(DateFormatter('%b/%y'))
        save(fig,a.saida/'casos_reais'/f'{ip.replace(".","_")}_datas.png')

    pd.DataFrame(case_rows).to_csv(a.saida/'casos_reais_mensal.csv',index=False)
    with open(a.saida/'LEIA-ME.txt','w',encoding='utf-8') as f:
        f.write(f'Gráficos temporais Cloud Telescope - {total} IPs\n\n')
        f.write(f'Período: {a.inicio_mes} até {a.fim_mes} (meses inclusivos).\n')
        f.write('Amostra selecionada conforme o CSV; confira as faixas de amostragem.\n')
        f.write('Silêncio de IP significa ausência de pacotes registrados, não prova de inatividade.\n')
        f.write('Medianas por grupo são calculadas só entre IPs com observação no mês.\n')
        f.write('Um gráfico de portas mostra SOMENTE quantas portas distintas foram observadas; NÃO identifica números específicos.\n')
        f.write('Grupos provisórios definidos por clusterização, não por rótulo de ataque.\n')
    print(f'Criados gráficos em {a.saida.resolve()}')
    print('Indicadores por grupo e casos reais exportados.')

if __name__=='__main__':
    main()
