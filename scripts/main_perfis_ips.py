
"""Seleciona IPs, reconstrói o histórico e exporta CSVs para a clusterização."""

import argparse
import os
import sqlite3
from pathlib import Path

from perfis_amostragem import selecionar
from perfis_historico import historico
from perfis_exportacao import exportar

# Escolhe qual fase executar: selecionar, reconstruir histórico ou exportar.
def main():
    p=argparse.ArgumentParser(description='Piloto estratificado para caracterizar perfis temporais de IPs no Cloud Telescope')
    p.add_argument('--fase',required=True,choices=('selecionar','historico','exportar'))
    p.add_argument('--banco',type=Path,default=Path('auditoria_integral/auditoria.sqlite'))
    p.add_argument('--zip',type=Path,default=Path('cloud_telescope_raw_dataset_3.zip'))
    p.add_argument('--saida',type=Path,default=Path('piloto_perfis'))
    p.add_argument('--baixa',type=int,default=500)
    p.add_argument('--media',type=int,default=1000)
    p.add_argument('--alta',type=int,default=1000)
    p.add_argument('--semente',type=int,default=42)
    p.add_argument('--senha',default=os.environ.get("CLOUD_TELESCOPE_ZIP_PASSWORD", ""))
    p.add_argument('--limitar-arquivos',type=int,default=0,help='0=todos; se positivo, teste inicial; retoma depois')
    p.add_argument('--somente-auditados',action='store_true',help='Na fase historico, ler apenas PCAPs concluidos no --banco da auditoria')
    p.add_argument('--relatorio-a-cada',type=int,default=100)
    a=p.parse_args()
    if min(a.baixa,a.media,a.alta,a.limitar_arquivos)>=0 and a.relatorio_a_cada>0:
        try:
            if a.fase=='selecionar': selecionar(a)
            elif a.fase=='historico': historico(a)
            else: exportar(a)
        except (ValueError,sqlite3.Error,OSError) as exc:
            p.error(str(exc))
    else:
        p.error('Parametros numericos invalidos')

if __name__ == "__main__":
    main()
