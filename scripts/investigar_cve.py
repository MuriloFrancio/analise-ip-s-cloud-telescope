
"""
Compara trafego de uma porta TCP antes e depois da divulgacao de uma CVE.
"""
import argparse
import os
import collections
import csv
import gzip
import hashlib
import json
import sqlite3
import sys
import time
import zipfile
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import matplotlib.dates as mdates

try:
    import pyzipper
except ImportError:
    pyzipper = None

from capturas import iterar_pcap, ler_campos, metadados


# Carrega o grupo G1–G7 de cada IP a partir do CSV da clusterização.
def ler_ips(caminho):
    ips={}
    with caminho.open(newline='',encoding='utf-8-sig') as f:
        rd=csv.DictReader(f)
        if not {'ip','grupo'}.issubset(rd.fieldnames or []):
            raise ValueError("CSV de clusters precisa conter colunas 'ip' e 'grupo'")
        for row in rd:
            ips[row['ip']] = int(row['grupo'])
    return ips


# Cria o SQLite da investigação e impede misturar execuções diferentes.
def configurar_banco(pasta, identidade):
    pasta.mkdir(parents=True, exist_ok=True)
    c=sqlite3.connect(pasta/'investigacao.sqlite',timeout=120)
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA busy_timeout=120000')
    c.executescript('''
      CREATE TABLE IF NOT EXISTS meta (chave TEXT PRIMARY KEY, valor TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS concluidos (arquivo TEXT PRIMARY KEY, status TEXT NOT NULL, erro TEXT);
      CREATE TABLE IF NOT EXISTS dia_todos (
        dia TEXT PRIMARY KEY, pacotes INTEGER NOT NULL, syn INTEGER NOT NULL,
        synack INTEGER NOT NULL, rst INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS ip_dia (
        ip TEXT NOT NULL, dia TEXT NOT NULL, regiao TEXT NOT NULL,
        pacotes INTEGER NOT NULL, syn INTEGER NOT NULL, synack INTEGER NOT NULL,
        rst INTEGER NOT NULL, PRIMARY KEY(ip,dia,regiao));
    ''')
    old=c.execute("SELECT valor FROM meta WHERE chave='identidade'").fetchone()
    if old and old[0]!=identidade:
        c.close()
        raise ValueError('ZIP/CSV/evento/porta diferentes da execucao anterior. Escolha outra pasta --saida.')
    with c:
        c.execute("INSERT OR IGNORE INTO meta VALUES('identidade',?)",(identidade,))
    return c


# Gera a identidade da investigação: ZIP, clusters, porta, data e janela.
def ident(args):
    st=args.zip.stat()
    sha=hashlib.sha256(args.clusters.read_bytes()).hexdigest()
    auditoria = None
    # Quando ativado, compara apenas os PCAPs aprovados na auditoria.
    if args.somente_auditados:
        with sqlite3.connect(args.banco) as base:
            nomes = sorted(row[0] for row in base.execute("SELECT arquivo FROM arquivos WHERE status='ok'"))
        auditoria = hashlib.sha256('\n'.join(nomes).encode('utf-8')).hexdigest()
    return json.dumps({
        'zip':str(args.zip.resolve()), 'zip_size':st.st_size, 'zip_mtime':st.st_mtime_ns,
        'clusters_sha256':sha, 'evento':args.evento, 'dias':args.dias,
        'porta':args.porta, 'auditoria_sha256':auditoria,
    },sort_keys=True)


# Soma as contagens do PCAP para a porta e marca o arquivo como concluído.
def salvar_arquivo(c, arquivo, dias, ips):
    with c:
        for day,(n,s,sa,r) in dias.items():
            c.execute('''INSERT INTO dia_todos VALUES(?,?,?,?,?)
              ON CONFLICT(dia) DO UPDATE SET
              pacotes=pacotes+excluded.pacotes,syn=syn+excluded.syn,
              synack=synack+excluded.synack,rst=rst+excluded.rst''',(day,n,s,sa,r))
        for (ip,day,reg),(n,s,sa,r) in ips.items():
            c.execute('''INSERT INTO ip_dia VALUES(?,?,?,?,?,?,?)
              ON CONFLICT(ip,dia,regiao) DO UPDATE SET
              pacotes=pacotes+excluded.pacotes,syn=syn+excluded.syn,
              synack=synack+excluded.synack,rst=rst+excluded.rst''',(ip,day,reg,n,s,sa,r))
        c.execute("INSERT OR REPLACE INTO concluidos VALUES(?,'ok',NULL)",(arquivo,))


# Relê PCAPs, filtra a porta TCP escolhida e associa pacotes aos grupos.
def analisar(args,c,ips,inicio,fim):
    cls=pyzipper.AESZipFile if pyzipper else zipfile.ZipFile
    with cls(args.zip,'r',allowZip64=True) as z:
        files=[x for x in z.infolist() if not x.is_dir() and x.filename.lower().endswith(('.pcap','.pcap.gz'))]
        files.sort(key=lambda x:x.filename)
        if args.somente_auditados:
            with sqlite3.connect(args.banco) as base:
                auditados = {r[0] for r in base.execute("SELECT arquivo FROM arquivos WHERE status='ok'")}
            files = [info for info in files if info.filename in auditados]
            if not files:
                raise ValueError('Nenhum PCAP concluido da auditoria foi encontrado no ZIP.')
        done={r[0] for r in c.execute("SELECT arquivo FROM concluidos WHERE status='ok'")}
        todo=[x for x in files if x.filename not in done]
        if args.max_arquivos:
            # Teste com arquivos distribuídos pelo ZIP; retoma depois.
            k=min(args.max_arquivos,len(todo))
            todo=[todo[round(i*(len(todo)-1)/max(k-1,1))] for i in range(k)] if k>1 else todo[:k]
        print(f'PCAPs selecionados: {len(files):,} | ja concluidos: {len(done):,} | novos: {len(todo):,}',flush=True)
        n_error=0
        for i,info in enumerate(todo,1):
            reg=metadados(info.filename)[0]
            res_todos=collections.defaultdict(lambda:[0,0,0,0])
            res_ips=collections.defaultdict(lambda:[0,0,0,0])
            vistos=0
            cache={}
            try:
                with z.open(info,pwd=args.senha.encode('utf-8') if args.senha else None) as bruto:
                    fonte=gzip.GzipFile(fileobj=bruto,mode='rb') if info.filename.lower().endswith('.gz') else bruto
                    with closing(fonte):
                        for ts,linktype,pkt in iterar_pcap(fonte):
                            if not (inicio <= ts < fim):
                                continue
                            proto,flags,typ,code,sport,dport,version,src=ler_campos(pkt,linktype,True)
                            # Mantém apenas TCP para a porta informada; isso não prova exploração da CVE.
                            if proto!=6 or dport!=args.porta:
                                continue
                            ed=int(ts)//86400
                            day=cache.get(ed)
                            if day is None:
                                day=datetime.fromtimestamp(ed*86400,timezone.utc).strftime('%Y-%m-%d')
                                cache[ed]=day
                            add=(1,int(bool(flags&2 and not flags&16)),int((flags&18)==18),int(bool(flags&4)))
                            a=res_todos[day]
                            for j in range(4): a[j]+=add[j]
                            if src in ips:
                                a=res_ips[(src,day,reg)]
                                for j in range(4): a[j]+=add[j]
                                vistos+=1
                salvar_arquivo(c,info.filename,res_todos,res_ips)
            except Exception as exc:
                n_error+=1
                with c:
                    c.execute("INSERT OR REPLACE INTO concluidos VALUES(?,'erro',?)",(info.filename,str(exc)[:350]))
                print(f'ERRO {info.filename}: {exc}',file=sys.stderr,flush=True)
            if i<=3 or i%args.relatorio_a_cada==0:
                print(f'[{i:,}/{len(todo):,}] selecionados na porta: {vistos:,} | {info.filename}',flush=True)
        print(f'Concluido. Erros nesta execucao: {n_error}.',flush=True)


# Consulta o SQLite e gera CSVs e gráficos sem reler as capturas.
def exportar(args,c,ips,evento):
    pasta=args.saida
    E = date.fromisoformat(evento)
    inicio = E - timedelta(days=args.dias)
    fim = E + timedelta(days=args.dias)

    # Limita o período às datas observadas na auditoria.
    if args.banco:
        with sqlite3.connect(args.banco) as auditoria:
            primeiro, ultimo = auditoria.execute("""
                SELECT MIN(primeiro_ts), MAX(ultimo_ts)
                FROM arquivos WHERE status = 'ok'
            """).fetchone()

        if primeiro is not None and ultimo is not None:
            inicio = max(inicio, datetime.fromtimestamp(primeiro, timezone.utc).date())
            fim = min(fim, datetime.fromtimestamp(ultimo, timezone.utc).date())

    if inicio > fim:
        raise ValueError("Nenhuma captura dentro do período selecionado.")

    datas = [
        inicio + timedelta(days=i)
        for i in range((fim - inicio).days + 1)
    ]
    def periodo(d):
        return 'antes' if d<E else 'evento' if d==E else 'depois'
    tudo={x[0]:x[1:] for x in c.execute('SELECT dia,pacotes,syn,synack,rst FROM dia_todos')}
    hist=collections.defaultdict(lambda:[0,0,0,0])
    regioes=collections.defaultdict(set)
    for ip,day,region,pac,syn,synack,rst in c.execute('SELECT ip,dia,regiao,pacotes,syn,synack,rst FROM ip_dia'):
        a=hist[(ip,day)]
        a[0]+=pac; a[1]+=syn; a[2]+=synack; a[3]+=rst
        regioes[(ip,day)].add(region)
    with (pasta/'por_ip_dia.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f); w.writerow(['ip','grupo','data_utc','periodo','pacotes','syn','synack','rst','regioes_distintas'])
        for (ip,day),counts in sorted(hist.items()):
            w.writerow([ip,ips[ip],day,periodo(date.fromisoformat(day)),*counts,len(regioes[(ip,day)])])
    sums=collections.defaultdict(lambda:collections.Counter())
    per_ips=collections.defaultdict(lambda:collections.Counter())
    for (ip,day),nums in hist.items():
        p=periodo(date.fromisoformat(day))
        key=(ips[ip],p)
        sums[key]['pacotes']+=nums[0]
        sums[key]['syn']+=nums[1]
        sums[key]['synack']+=nums[2]
        sums[key]['rst']+=nums[3]
        per_ips[key][ip]+=nums[0]
    with (pasta/'comparacao_clusters.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f); w.writerow(['grupo','periodo','ips_no_grupo','ips_que_sondaram_porta','pacotes','syn','synack','rst'])
        cnt=collections.Counter(ips.values())
        for g in sorted(cnt):
            for p in ['antes','evento','depois']:
                q=sums[(g,p)]; w.writerow([f'G{g}',p,cnt[g],len(per_ips[(g,p)]),q['pacotes'],q['syn'],q['synack'],q['rst']])
    por_ip=collections.defaultdict(lambda:collections.Counter())
    dias_por_ip=collections.defaultdict(lambda:collections.Counter())
    diario_grupo=collections.defaultdict(lambda:collections.Counter())
    ips_diario_grupo=collections.defaultdict(set)
    for (ip,day),nums in hist.items():
        pp=periodo(date.fromisoformat(day))
        por_ip[ip][pp]+=nums[0]
        dias_por_ip[ip][pp]+=1
        diario_grupo[(day,ips[ip])]['pacotes']+=nums[0]
        ips_diario_grupo[(day,ips[ip])].add(ip)
    with (pasta/'por_ip_periodo.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f); w.writerow(['ip','grupo','pacotes_antes','pacotes_evento','pacotes_depois','dias_antes','dias_depois'])
        for ip in sorted(ips):
            pac=por_ip[ip]; ds=dias_por_ip[ip]
            w.writerow([ip,f'G{ips[ip]}',pac['antes'],pac['evento'],pac['depois'],ds['antes'],ds['depois']])
    with (pasta/'serie_diaria_clusters.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f); w.writerow(['data_utc','grupo','periodo','pacotes_porta','ips_distintos_porta'])
        for d in datas:
            for g in sorted(set(ips.values())):
                y=d.isoformat()
                w.writerow([y,f'G{g}',periodo(d),diario_grupo[(y,g)]['pacotes'],len(ips_diario_grupo[(y,g)])])
    with (pasta/'serie_diaria_porta.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.writer(f); w.writerow(['data_utc','periodo','pacotes_pcaps_analisados','pacotes_ips_amostra','ips_distintos_amostra','syn_pcaps_analisados'])
        for day in datas:
            y=day.isoformat()
            ip_dias=[(ip,q[0]) for (ip,d),q in hist.items() if d==y]
            w.writerow([y,periodo(day),tudo.get(y,(0,0,0,0))[0],sum(q for ip,q in ip_dias),len(ip_dias),tudo.get(y,(0,0,0,0))[1]])
    ok=c.execute("SELECT COUNT(*) FROM concluidos WHERE status='ok'").fetchone()[0]
    errors=c.execute("SELECT COUNT(*) FROM concluidos WHERE status='erro'").fetchone()[0]
    totals={p:sum(v[0] for day,v in tudo.items() if periodo(date.fromisoformat(day))==p) for p in ['antes','evento','depois']}
    resumo={'evento':evento,'porta_tcp_destino':args.porta,'dias_antes_depois':args.dias,
            'ips_selecionados':len(ips),'pcaps_ok':ok,'pcaps_com_erro':errors,
            'limitado_aos_pcaps_da_auditoria':args.somente_auditados,
            'totais_pcaps_analisados':totals,'pacotes_amostra_na_porta':sum(v[0] for v in hist.values()),
            'nota':'Contagens representam apenas os PCAPs selecionados. Trafego na porta nao comprova exploracao da CVE; ausencia pode refletir cobertura limitada.'}
    (pasta/'resumo_evento.json').write_text(json.dumps(resumo,indent=2,ensure_ascii=False),encoding='utf-8')
    try:
        import matplotlib.pyplot as plt
        rows=[]
        with (pasta/'serie_diaria_porta.csv').open(encoding='utf-8-sig',newline='') as f:
            rows=list(csv.DictReader(f))
        xs=[datetime.strptime(q['data_utc'],'%Y-%m-%d').date() for q in rows]
        valores = [int(q["pacotes_pcaps_analisados"]) for q in rows]

        # Média móvel dos últimos sete dias.
        # A linha suavizada é calculada com os últimos sete dias da série.
        media_7d = [
            sum(valores[max(0, i-6):i+1]) / min(i+1, 7)
            for i in range(len(valores))
        ]

        plt.figure(figsize=(13, 5.2))

        plt.plot(xs, valores, alpha=0.5, label="Pacotes/dia")
        plt.plot(xs, media_7d, linewidth=2, label="Média móvel (7 dias)")

        plt.axvline(E, linestyle="--", label="Divulgação da CVE")

        if fim >= date(2024, 3, 1):
            plt.axvspan(
                date(2024, 3, 1), fim,
                alpha=0.08,
                label="Março (parcial)"
            )

        plt.title(f"TCP/{args.porta} — todos os IPs do Cloud Telescope")
        plt.ylabel("Pacotes por dia")
        plt.xlabel("Data UTC")

        plt.gca().xaxis.set_major_locator(mdates.MonthLocator())
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter("%b/%Y"))

        plt.grid(alpha=0.15)
        plt.legend()
        plt.tight_layout()

        plt.savefig(pasta / "grafico_porta_todo_dataset.png", dpi=160)
        plt.close()
        plt.figure(figsize=(10,4.5))
        plt.plot(xs,[int(q['pacotes_ips_amostra']) for q in rows],label=f'{len(ips)} IPs da amostra')
        plt.axvline(E,linestyle='--',label='Divulgacao da CVE')
        plt.title(f'IPs clusterizados: trafego TCP/{args.porta} (UTC)')
        plt.ylabel('Pacotes/dia');plt.xlabel('Data');plt.legend();plt.xticks(rotation=35)
        plt.tight_layout();plt.savefig(pasta/'grafico_porta_amostra.png',dpi=150);plt.close()
        plt.figure(figsize=(10,5))
        for g in sorted(set(ips.values())):
            plt.plot(xs,[diario_grupo[(d.isoformat(),g)]['pacotes'] for d in datas],label=f'G{g}')
        plt.axvline(E,linestyle='--',label='Divulgacao da CVE')
        plt.title(f'Porta TCP/{args.porta}: atividade diaria por cluster')
        plt.ylabel('Pacotes/dia');plt.xlabel('Data');plt.xticks(rotation=35);plt.legend(ncol=4)
        plt.tight_layout();plt.savefig(pasta/'grafico_clusters_porta.png',dpi=150);plt.close()
    except ImportError:
        print('Matplotlib ausente: CSVs criados, graficos PNG nao gerados.')
    if not any(totals.values()):
        print('AVISO: nenhum pacote dessa porta foi encontrado nos PCAPs da janela. Isso nao prova ausencia no dataset completo.')
    print(json.dumps(resumo,indent=2,ensure_ascii=False))
    print('Arquivos em:',pasta.resolve())


# Valida parâmetros e decide entre analisar PCAPs ou só exportar.
def main():
    p=argparse.ArgumentParser(description='Investiga trafego dirigido a uma porta em torno da divulgacao de uma CVE')
    p.add_argument('--zip',type=Path,required=True)
    p.add_argument('--clusters',type=Path,required=True)
    p.add_argument('--banco',type=Path,help='SQLite da auditoria inicial')
    p.add_argument('--somente-auditados',action='store_true',help='Reutiliza apenas PCAPs concluidos na auditoria')
    p.add_argument('--saida',type=Path,default=Path('estudo_cve'))
    p.add_argument('--evento',default='2023-10-27')
    p.add_argument('--porta',type=int,default=61616)
    p.add_argument('--dias',type=int,default=14)
    p.add_argument('--senha',default=os.environ.get("CLOUD_TELESCOPE_ZIP_PASSWORD", ""))
    p.add_argument('--relatorio-a-cada',type=int,default=100)
    p.add_argument('--max-arquivos',type=int,default=0,help='Teste inicial; 0 = processa todos ainda nao concluidos')
    p.add_argument('--somente-exportar',action='store_true')
    args=p.parse_args()
    E=date.fromisoformat(args.evento)
    if not(0<=args.porta<=65535) or args.dias<1 or args.relatorio_a_cada<1 or args.max_arquivos<0:
        p.error('porta/dias/relatorio-a-cada/max-arquivos invalidos')
    if not args.zip.is_file() or not args.clusters.is_file():
        p.error('ZIP ou CSV de clusters nao encontrado')
    if args.somente_auditados and (args.banco is None or not args.banco.is_file()):
        p.error('Para --somente-auditados, informe --banco com um SQLite existente')
    ips=ler_ips(args.clusters)
    if not ips: p.error('Nenhum IP encontrado no CSV')
    c=configurar_banco(args.saida,ident(args))
    try:
        start=datetime.combine(E-timedelta(days=args.dias),datetime.min.time(),timezone.utc).timestamp()
        stop=datetime.combine(E+timedelta(days=args.dias+1),datetime.min.time(),timezone.utc).timestamp()
        if not args.somente_exportar:
            analisar(args,c,ips,start,stop)
        exportar(args,c,ips,args.evento)
    finally:
        c.close()

if __name__=='__main__':
    main()
