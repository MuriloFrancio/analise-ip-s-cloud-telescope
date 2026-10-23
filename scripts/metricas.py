"""Cálculo de estatísticas por pacote, hora, porta e IP de origem."""

import collections
import gzip
from contextlib import closing
from datetime import datetime, timezone

from banco import FIELDS
from capturas import iterar_pcap, ler_campos

# Contadores definidos na ordem das colunas do SQLite

# Cria um contador zerado seguindo a ordem de campos do SQLite.
def nova_contagem():
    """Inicializa as métricas na ordem definida em FIELDS."""
    return [0] * len(FIELDS)


# Conta o pacote e incrementa seus indicadores de protocolo e flags.
def atualizar(c, proto, flags, tipo_icmp, versao):
    """Atualiza os contadores de um pacote."""
    c[0] += 1
    if proto == 6:
        c[1] += 1
        if flags & 2 and not flags & 16:
            c[6] += 1
        if flags & 2 and flags & 16:
            c[7] += 1
        if flags & 4:
            c[8] += 1
        if flags & 4 and flags & 16:
            c[9] += 1
    elif proto == 17:
        c[2] += 1
    elif proto in (1,58):
        c[3] += 1
        if tipo_icmp == 0 and proto == 1:
            c[10] += 1
        if (proto == 1 and tipo_icmp in (3,4,5,11,12)) or (proto == 58 and tipo_icmp in (1,2,3,4)):
            c[11] += 1
    if versao == 4:
        c[4] += 1
    elif versao == 6:
        c[5] += 1


# Faz as agregações de um PCAP antes de enviá-las ao banco.
def analisar_pcap(z, info, region, prefixo_mascara, senha, perfil_origens):
    """Processa uma captura e reúne suas estatísticas em memória."""
    resumo = nova_contagem()
    por_hora = collections.defaultdict(nova_contagem)
    dest = collections.Counter()
    respostas = collections.Counter()
    flags_c = collections.Counter()
    icmp_c = collections.Counter()
    origens = {} if perfil_origens else None
    exemplos = []
    primeiro = ultimo = None
    cache_hora = None
    dia = None
    # Abre o arquivo do ZIP; se for .gz, descomprime enquanto lê.
    with z.open(info, pwd=senha.encode("utf-8") if senha else None) as bruto:
        fonte = gzip.GzipFile(fileobj=bruto, mode="rb") if info.filename.lower().endswith(".gz") else bruto
        with closing(fonte):
            for ts, linktype, dados in iterar_pcap(fonte):
                if not 0 <= ts < 4_102_444_800:  # 1970 a 2100
                    continue
                h = int(ts // 3600)
                if h != cache_hora:
                    cache_hora = h
                    dia = datetime.fromtimestamp(h * 3600, tz=timezone.utc).strftime("%Y-%m-%d")
                proto, f, tipo_icmp, codigo, srcport, dstport, versao, ip = ler_campos(
                    dados, linktype, perfil_origens
                )
                atualizar(resumo, proto, f, tipo_icmp, versao)
                atualizar(por_hora[h], proto, f, tipo_icmp, versao)
                if primeiro is None or ts < primeiro:
                    primeiro = ts
                if ultimo is None or ts > ultimo:
                    ultimo = ts
                if proto in (6, 17) and dstport >= 0:
                    nome_proto = "TCP" if proto == 6 else "UDP"
                    dest[(dia, nome_proto, dstport, 0)] += 1
                    if proto == 6 and f & 2 and not f & 16:
                        dest[(dia, nome_proto, dstport, 1)] += 1
                if proto == 6:
                    flags_c[f] += 1
                    if srcport >= 0 and (f & 4 or (f & 18) == 18):
                        if f & 18 == 18:
                            respostas[(dia, srcport, 0)] += 1
                        if f & 4:
                            respostas[(dia, srcport, 1)] += 1
                if proto in (1,58) and tipo_icmp >= 0:
                    icmp_c[(versao, tipo_icmp, codigo)] += 1
                # Só monta contagens por IP quando --perfil-origens está ativo.
                if perfil_origens and ip:
                    s = origens.get(ip)
                    if s is None:
                        s = [0, 0, 0, 0, prefixo_mascara, set(), ts, ts]
                        origens[ip] = s
                    s[0] += 1
                    s[1] += int(proto == 6 and (f & 2) != 0 and (f & 16) == 0)
                    s[2] += int(proto == 6 and (f & 18) == 18)
                    s[3] += int(proto == 6 and (f & 4) != 0)
                    if proto in (6, 17) and dstport >= 0:
                        s[5].add((proto, dstport))
                    if ts < s[6]:
                        s[6] = ts
                    if ts > s[7]:
                        s[7] = ts
                # Exemplos limitados a dez registros por PCAP.
                if len(exemplos) < 10 and (
                    (proto == 6 and ((f & 18) == 18 or (f & 4)))
                    or (proto in (1,58) and tipo_icmp in (0,3,11))
                ):
                    if ip is None:
                        _, _, _, _, _, _, _, ip = ler_campos(dados, linktype, True)
                    exemplos.append((info.filename, datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                                     region, "TCP" if proto == 6 else "ICMP", ip,
                                     srcport if srcport >= 0 else None,
                                     dstport if dstport >= 0 else None,
                                     str(f) if proto == 6 else None,
                                     tipo_icmp if tipo_icmp >= 0 else None,
                                     codigo if codigo >= 0 else None))
    dest_agregado = {}
    for (d, proto, port, kind), n in dest.items():
        k = (d, proto, port)
        c = dest_agregado.setdefault(k, [0, 0])
        c[kind] += n
    resp_agregado = {}
    for (d, port, kind), n in respostas.items():
        k = (d, port)
        c = resp_agregado.setdefault(k, [0, 0])
        c[kind] += n
    return resumo, por_hora, dest_agregado, resp_agregado, flags_c, icmp_c, origens, exemplos, primeiro, ultimo
