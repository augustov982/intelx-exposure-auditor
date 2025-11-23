#!/usr/bin/env python3
"""
IntelX Exposure Auditor
Autor: Augusto V.
Descrição: Ferramenta de OSINT para consultar a API da Intelligence X e verificar
se alvos (e-mails) possuem dados expostos em vazamentos públicos (Data Breaches).
Uso: Ideal para equipes de Blue Team e Security Operations (SecOps) monitorarem a exposição de VIPs.

DISCLAIMER:
Esta ferramenta foi desenvolvida para fins educacionais e auditorias de segurança autorizadas.
O uso indevido de informações obtidas é de total responsabilidade do usuário.
"""

import requests
import time
import datetime
import os
import argparse
import re
import sys
from typing import Optional, List

# Configurações globais via Variáveis de Ambiente (Segurança)
# No Linux/Mac: export INTELX_KEY="sua-chave-aqui"
API_KEY = os.getenv('INTELX_KEY')
BASE_URL = 'https://2.intelx.io'
HEADERS = {
    'x-key': API_KEY,
    'Content-Type': 'application/json',
    'User-Agent': 'IntelX-Auditor-Tool/1.0'
}

# Regex para validação simples de e-mail
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

class IntelXClient:
    def __init__(self):
        if not API_KEY:
            print("[-] ERRO CRÍTICO: A variável de ambiente 'INTELX_KEY' não está definida.")
            print("    Por favor, configure-a antes de executar o script.")
            sys.exit(1)

    def search(self, term: str, buckets: List[str] = None, max_results: int = 100) -> Optional[str]:
        """
        Inicia uma pesquisa na IntelX.
        Retorna o ID da pesquisa (search_id) ou None em caso de erro.
        """
        if buckets is None:
            buckets = ['leaks.public.general']

        # Define janela de tempo (ex: últimos 90 dias ou busca geral)
        # Para auditoria completa, removemos o datefrom/dateto restrito ou configuramos via args
        
        url = f'{BASE_URL}/intelligent/search'
        payload = {
            "term": term,
            "buckets": buckets,
            "maxresults": max_results,
            "media": 0, # 0 = All types
            "sort": 4,  # Date desc
            "timeout": 5
        }

        try:
            response = requests.post(url, json=payload, headers=HEADERS, timeout=30)
            if response.status_code == 200:
                search_id = response.json().get('id')
                return search_id
            elif response.status_code == 402:
                print(f"[-] Limite da API atingido ou licença expirada (Erro 402).")
                return None
            else:
                print(f"[-] Erro na API ({response.status_code}): {response.text}")
                return None
        except Exception as e:
            print(f"[-] Erro de conexão: {e}")
            return None

    def get_results(self, search_id: str, limit: int = 50):
        """
        Obtém os metadados dos resultados da pesquisa.
        """
        url = f'{BASE_URL}/intelligent/search/result'
        params = {"id": search_id, "limit": limit, "offset": 0}
        
        # Pequeno delay para garantir que a IntelX processou a busca inicial
        time.sleep(2) 

        try:
            response = requests.get(url, headers=HEADERS, params=params, timeout=30)
            if response.status_code == 200:
                return response.json().get('records', [])
            return []
        except Exception as e:
            print(f"[-] Erro ao recuperar resultados: {e}")
            return []

    def export_data(self, search_id: str, output_dir: str):
        """
        Baixa o dump dos dados encontrados (se a licença permitir).
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        file_path = os.path.join(output_dir, f'intelx_export_{search_id}.zip')
        if os.path.exists(file_path):
            print(f"[!] Arquivo já existe: {file_path}")
            return

        url = f'{BASE_URL}/intelligent/search/export'
        params = {"id": search_id, "f": 1, "k": API_KEY} # f=1 (format zip)

        print(f"[*] Iniciando download do dump para ID: {search_id}...")
        try:
            with requests.get(url, headers=HEADERS, params=params, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(file_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            print(f"[+] Download concluído: {file_path}")
        except Exception as e:
            print(f"[-] Falha no download: {e}")

def process_target(target: str, client: IntelXClient, download: bool):
    print(f"\n[*] Auditando alvo: {target}")
    
    # 1. Buscar
    # Bucket 'leaks.public.general' foca em vazamentos de dados
    search_id = client.search(target, buckets=['leaks.public.general'])
    
    if not search_id:
        print("[-] Não foi possível iniciar a pesquisa.")
        return

    print(f"[+] Search ID gerado: {search_id}")
    
    # 2. Listar Resultados
    records = client.get_results(search_id)
    
    if not records:
        print("[*] Nenhum registro de vazamento encontrado (Clean).")
        return

    print(f"[!] ALERTA: Encontrados {len(records)} registros potenciais de vazamento.")
    
    for rec in records[:5]: # Mostra apenas os 5 primeiros no console
        date = rec.get('date', 'N/A')
        name = rec.get('name', 'Sem Nome')
        print(f"    -> {date} | {name}")

    # 3. Download (Opcional)
    if download:
        client.export_data(search_id, output_dir='reports_downloads')

def main():
    parser = argparse.ArgumentParser(description="IntelX Exposure Auditor - OSINT Tool")
    parser.add_argument("-t", "--target", help="E-mail único para auditoria")
    parser.add_argument("-f", "--file", help="Arquivo de texto contendo lista de e-mails (um por linha)")
    parser.add_argument("--download", action="store_true", help="Baixar os dados brutos (ZIP) se encontrados")
    
    args = parser.parse_args()
    client = IntelXClient()

    if args.target:
        if EMAIL_REGEX.match(args.target):
            process_target(args.target, client, args.download)
        else:
            print("[-] Formato de e-mail inválido.")

    elif args.file:
        if not os.path.exists(args.file):
            print(f"[-] Arquivo não encontrado: {args.file}")
            return
        
        with open(args.file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if EMAIL_REGEX.match(line.strip())]
        
        print(f"[*] Carregados {len(targets)} alvos do arquivo.")
        for target in targets:
            process_target(target, client, args.download)
            time.sleep(2) # Respeitar Rate Limiting da API
    else:
        parser.print_help()

if __name__ == '__main__':
    main()