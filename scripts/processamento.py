"""Seleção de PCAPs, execução incremental e retomada do processamento."""

import collections
import json
import sys
import time
import zipfile

from banco import conectar, salvar
from capturas import metadados
from exportacao import exportar
from metricas import analisar_pcap

try:
    import pyzipper
except ImportError:
    pyzipper = None

# Distribui testes pequenos entre meses e regiões, evitando pegar um único período.
def selecionar_amostra(arquivos, limite):
    """Seleciona PCAPs distribuídos entre meses e regiões AWS."""
    grupos = collections.defaultdict(list)
    for item in arquivos:
        regiao, _, data_nome, _ = metadados(item.filename)
        grupos[(data_nome[:6], regiao)].append(item)

    escolhidos = []
    por_mes = collections.Counter()
    por_regiao = collections.Counter()
    chaves = list(grupos)

    while len(escolhidos) < limite and chaves:
        chave = min(chaves, key=lambda k: (por_mes[k[0]], por_regiao[k[1]], k))
        escolhidos.append(grupos[chave].pop(len(grupos[chave]) // 2))
        por_mes[chave[0]] += 1
        por_regiao[chave[1]] += 1
        if not grupos[chave]:
            chaves.remove(chave)

    return escolhidos


# Coordena os PCAPs pendentes, salva cada resultado e permite retomar uma execução.
def executar(args, parser):
    """Executa a análise ou exportação conforme os parâmetros recebidos."""
    if args.max_arquivos < 0 or args.relatorio_a_cada < 1:
        parser.error("Parametros numericos invalidos")

    args.saida.mkdir(parents=True, exist_ok=True)
    con = conectar(args.saida / "auditoria.sqlite")

    try:
        if args.somente_exportar:
            exportar(con, args.saida)
            return
        if args.zip is None or not args.zip.is_file():
            parser.error(f"Informe um ZIP existente em --zip: {args.zip}")

        assinatura = json.dumps({
            "arquivo": str(args.zip.resolve()),
            "tamanho": args.zip.stat().st_size,
            "modificado_ns": args.zip.stat().st_mtime_ns,
        })
        anterior = con.execute(
            "SELECT valor FROM meta WHERE chave='zip_signature'"
        ).fetchone()
        if anterior and anterior[0] != assinatura:
            parser.error("O ZIP/caminho mudou. Use nova pasta --saida para evitar misturar fontes.")

        perfil = "1" if args.perfil_origens else "0"
        anterior = con.execute(
            "SELECT valor FROM meta WHERE chave='perfil_origens'"
        ).fetchone()
        if anterior and anterior[0] != perfil:
            parser.error("--perfil-origens mudou. Para alternar, use outro diretorio --saida.")

        with con:
            con.execute("INSERT OR IGNORE INTO meta VALUES ('zip_signature', ?)", (assinatura,))
            con.execute("INSERT OR IGNORE INTO meta VALUES ('perfil_origens', ?)", (perfil,))

        # Lê os nomes já registrados para não contabilizar o mesmo PCAP duas vezes.
        concluidos = {
            nome: status
            for nome, status in con.execute("SELECT arquivo, status FROM arquivos")
        }
        zip_class = pyzipper.AESZipFile if pyzipper is not None else zipfile.ZipFile
        if pyzipper is None:
            print("AVISO: pyzipper ausente; ZIPs AES exigem: py -m pip install pyzipper", flush=True)

        with zip_class(args.zip, "r", allowZip64=True) as z:
            arquivos = [
                item for item in z.infolist()
                if not item.is_dir() and item.filename.lower().endswith((".pcap", ".pcap.gz"))
            ]
            arquivos.sort(key=lambda item: (
                metadados(item.filename)[2],
                metadados(item.filename)[0],
                item.filename,
            ))
            regioes = sorted({metadados(item.filename)[0] for item in arquivos})
            if len(regioes) > 60:
                parser.error("Muitas regioes inesperadas no inventario; confirme a estrutura dos nomes")
            bits_regioes = {regiao: 1 << i for i, regiao in enumerate(regioes)}

            pendentes = [
                item for item in arquivos
                if item.filename not in concluidos
                or (args.repetir_erros and concluidos[item.filename] == "erro")
            ]
            if args.max_arquivos:
                pendentes = selecionar_amostra(pendentes, args.max_arquivos)

            print(
                f"ZIP: {len(arquivos):,} PCAPs | ja registrados: {len(concluidos):,} | "
                f"novos nesta execucao: {len(pendentes):,}",
                flush=True,
            )
            inicio_geral = time.monotonic()

            for posicao, item in enumerate(pendentes, 1):
                regiao, zona, data_nome, hora_nome = metadados(item.filename)
                inicio = time.monotonic()

                try:
                    estatisticas = analisar_pcap(
                        z, item, regiao, bits_regioes[regiao], args.senha, args.perfil_origens
                    )
                    if item.filename in concluidos:
                        with con:
                            con.execute(
                                "DELETE FROM arquivos WHERE arquivo=? AND status='erro'",
                                (item.filename,),
                            )
                    salvar(
                        con, item.filename, regiao, zona, data_nome,
                        hora_nome, estatisticas, time.monotonic() - inicio,
                    )
                    total_pacotes = estatisticas[0][0]
                    if posicao <= 3 or posicao % args.relatorio_a_cada == 0:
                        print(
                            f"[{posicao}/{len(pendentes)}] OK {total_pacotes:,} pacotes | "
                            f"SYN {estatisticas[0][6]:,} | SYN-ACK {estatisticas[0][7]:,} | "
                            f"{time.monotonic() - inicio:.1f}s | {item.filename}",
                            flush=True,
                        )
                except Exception as erro:
                    with con:
                        con.execute(
                            "INSERT OR REPLACE INTO arquivos"
                            "(arquivo,status,regiao,zona,data_nome,hora_nome,erro) "
                            "VALUES(?,?,?,?,?,?,?)",
                            (item.filename, "erro", regiao, zona, data_nome, hora_nome, str(erro)[:500]),
                        )
                    print(
                        f"[{posicao}/{len(pendentes)}] ERRO em {item.filename}: {erro}",
                        file=sys.stderr, flush=True,
                    )

                if posicao % args.relatorio_a_cada == 0:
                    velocidade = posicao / max(1, time.monotonic() - inicio_geral)
                    horas_restantes = (len(pendentes) - posicao) / max(velocidade, 0.0001) / 3600
                    print(
                        f"  Progresso: {posicao:,}/{len(pendentes):,} | "
                        f"{velocidade:.2f} arquivos/s | restante ~{horas_restantes:.1f} h (estimativa)",
                        flush=True,
                    )

        exportar(con, args.saida)
    except KeyboardInterrupt:
        print(
            "\nInterrompido. Resultados de arquivos concluidos estao no SQLite. "
            "Execute novamente para retomar.",
            file=sys.stderr,
        )
        sys.exit(130)
    finally:
        con.close()
