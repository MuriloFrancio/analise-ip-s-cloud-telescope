"""Identificação de arquivos e leitura binária de capturas PCAP clássicas."""

import ipaddress
import re
import struct
from pathlib import Path

# Assinaturas do PCAP e padrões de nome
# Estas assinaturas dizem a ordem dos bytes e a precisão do horário no PCAP clássico.
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
# Os padrões abaixo dependem do nome dos arquivos do Cloud Telescope.
DATA_RE = re.compile(r"-(20\d{6})-(\d{4})\.pcap(?:\.gz)?$", re.I)
ZONA_RE = re.compile(r"^(.+?)-\d{1,3}(?:\.\d{1,3}){3}-20\d{6}-")


# Tira região, zona, data e hora do nome do arquivo, sem abrir o PCAP.
def metadados(nome):
    """Identifica região, zona AWS, data e hora pelo nome do PCAP."""
    base = Path(nome).name
    m = DATA_RE.search(base)
    zona_m = ZONA_RE.search(base)
    zona = zona_m.group(1) if zona_m else "desconhecida"
    reg = re.sub(r"(?<=\d)[a-z]$", "", zona)
    return reg, zona, m.group(1) if m else "", m.group(2) if m else ""


# Lê os pacotes um por um; não carrega uma captura inteira na memória.
def iterar_pcap(arquivo):
    """Lê pacotes do PCAP clássico sem carregar o arquivo inteiro."""
    cab = arquivo.read(24)
    if len(cab) != 24 or cab[:4] not in MAGICS:
        raise ValueError("Cabeçalho PCAP nao suportado (PCAPNG ou arquivo corrompido)")
    ordem, resol = MAGICS[cab[:4]]
    linktype = struct.unpack(ordem + "IHHIIII", cab)[-1] & 0xFFFF
    unpack = struct.Struct(ordem + "IIII").unpack
    while True:
        h = arquivo.read(16)
        if not h:
            return
        if len(h) != 16:
            raise ValueError("Cabecalho de pacote truncado")
        segundos, fracao, capturado, _ = unpack(h)
        if capturado > 32_000_000:
            raise ValueError("Tamanho de pacote invalido")
        dados = arquivo.read(capturado)
        if len(dados) != capturado:
            raise ValueError("Pacote truncado")
        yield segundos + fracao / resol, linktype, dados


# Interpreta cabeçalhos IP/TCP/UDP/ICMP e devolve só os campos necessários.
def ler_campos(dados, linktype, extrair_ip=False):
    """Extrai protocolo, flags, ICMP, portas, versão IP e IP de origem."""
    versao = 0
    inicio = 0
    # Cada linktype indica como encontrar o cabeçalho IP dentro do pacote.
    if linktype == 1:
        if len(dados) < 14:
            return (0, 0, -1, -1, -1, -1, 0, None)
        tipo = (dados[12] << 8) | dados[13]
        inicio = 14
        while tipo in (0x8100, 0x88a8, 0x9100):
            if len(dados) < inicio + 4:
                return (0, 0, -1, -1, -1, -1, 0, None)
            tipo = (dados[inicio + 2] << 8) | dados[inicio + 3]
            inicio += 4
        if tipo not in (0x0800, 0x86dd):
            return (0, 0, -1, -1, -1, -1, 0, None)
    elif linktype == 101:
        inicio = 0
    elif linktype == 113:
        inicio = 16
    elif linktype == 276:
        inicio = 20
    else:
        return (0, 0, -1, -1, -1, -1, 0, None)
    if len(dados) <= inicio:
        return (0, 0, -1, -1, -1, -1, 0, None)
    versao = dados[inicio] >> 4
    ip_src = None
    if versao == 4:
        if len(dados) < inicio + 20:
            return (0, 0, -1, -1, -1, -1, 0, None)
        ihl = (dados[inicio] & 15) * 4
        if ihl < 20 or len(dados) < inicio + ihl:
            return (0, 0, -1, -1, -1, -1, 0, None)
        proto = dados[inicio + 9]
        if extrair_ip:
            ip_src = str(ipaddress.IPv4Address(dados[inicio+12:inicio+16]))
        deslocamento = ((dados[inicio+6] & 0x1f) << 8) | dados[inicio+7]
        offset = inicio + ihl if deslocamento == 0 else len(dados)
    elif versao == 6:
        if len(dados) < inicio + 40:
            return (0, 0, -1, -1, -1, -1, 0, None)
        proto = dados[inicio + 6]
        if extrair_ip:
            ip_src = str(ipaddress.IPv6Address(dados[inicio+8:inicio+24]))
        offset = inicio + 40
        for _ in range(8):
            if proto not in (0, 43, 44, 60):
                break
            if offset + 2 > len(dados):
                offset = len(dados)
                break
            prox = dados[offset]
            largura = 8 if proto == 44 else (dados[offset+1] + 1) * 8
            if offset + largura > len(dados):
                offset = len(dados)
                break
            if proto == 44 and ((dados[offset+2] << 8 | dados[offset+3]) & 0xfff8):
                offset = len(dados)
                break
            offset += largura
            proto = prox
    else:
        return (0, 0, -1, -1, -1, -1, 0, None)
    porta_src = porta_dst = tipo_icmp = codigo = -1
    flags = 0
    if proto in (6,17) and offset + 4 <= len(dados):
        porta_src = (dados[offset] << 8) | dados[offset+1]
        porta_dst = (dados[offset+2] << 8) | dados[offset+3]
    if proto == 6 and offset + 14 <= len(dados):
        flags = dados[offset+13]
    elif proto in (1,58) and offset + 2 <= len(dados):
        tipo_icmp, codigo = dados[offset], dados[offset+1]
    return (proto, flags, tipo_icmp, codigo, porta_src, porta_dst, versao, ip_src)
