# 🛡️ IntelX Exposure Auditor

> **Ferramenta de OSINT para Threat Intelligence e Auditoria de Vazamentos.**

Este projeto é uma solução automatizada desenvolvida em Python para consultar a API da **Intelligence X**. O objetivo principal é auxiliar equipes de Segurança (Blue Team) e Analistas de SOC a identificarem, de forma proativa, se credenciais corporativas ou dados sensíveis foram expostos em vazamentos públicos (Data Breaches).

## 🚀 Funcionalidades

- 🔍 **Busca Precisa:** Verifica a exposição de e-mails individuais ou listas corporativas.
- 📂 **Processamento em Lote:** Suporte a leitura de arquivos `.txt` para auditoria de múltiplos alvos.
- 🛡️ **Segurança Operacional (OpSec):** Gerenciamento de credenciais de API via variáveis de ambiente (sem chaves hardcoded).
- ⬇️ **Coleta de Evidências:** Capacidade de download automático dos dumps brutos para análise forense (se configurado).
- 📊 **Logs Claros:** Saída visual formatada para fácil leitura no terminal.

## ⚙️ Instalação

Certifique-se de ter o Python 3+ instalado.

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt

   🔐 Configuração (Segurança)
Para garantir a segurança das credenciais, esta ferramenta não armazena a chave de API no código fonte. Você deve exportá-la como variável de ambiente.
Linux / Mac:
export INTELX_KEY="sua-chave-api-aqui-0000-0000"
Windows (Powershell):
$env:INTELX_KEY="sua-chave-api-aqui-0000-0000"

💻 Como Usar
1. Auditar um único alvo
Verifique rapidamente se um e-mail específico foi comprometido:
python IntelX_Exposure_Auditor.py -t usuario@empresa.com

2. Auditar uma lista de funcionários
Para auditorias massivas, forneça um arquivo de texto (um e-mail por linha):
python IntelX_Exposure_Auditor.py -f lista_colaboradores.txt

3. Baixar evidências (Dumps)
Adicione a flag --download para baixar os arquivos originais (.zip) onde os dados foram encontrados:
python IntelX_Exposure_Auditor.py -t admin@alvo.com --download

⚠️ Disclaimer (Aviso Legal)
Esta ferramenta foi desenvolvida exclusivamente para fins educacionais e auditorias de segurança autorizadas.
O autor não se responsabiliza pelo uso indevido desta ferramenta.
O acesso a dados de terceiros sem consentimento pode ser ilegal.
Utilize apenas em alvos que você possui permissão para auditar ou em seus próprios dados (Self-Audit).

👨‍💻 Autor
Desenvolvido por Augusto V.
