# Guia de Uso do HashVerify

Este documento fornece instruções detalhadas sobre como usar o HashVerify.

## 📋 Índice

- [Instalação](#instalação)
- [Uso Básico](#uso-básico)
- [Configuração da API](#configuração-da-api)
- [Exportação de Relatórios](#exportação-de-relatórios)
- [Uso Avançado](#uso-avançado)
- [Troubleshooting](#troubleshooting)

## Instalação

### Método 1: Uso Direto (Sem Instalação)

```bash
# Clone o repositório
git clone https://github.com/slashline15/hashverify.git
cd hashverify

# Instale as dependências
pip install -r requirements.txt

# Execute
python -m hashverify
```

### Método 2: Instalação como Pacote

```bash
# Clone e instale
git clone https://github.com/slashline15/hashverify.git
cd hashverify
pip install -e .

# Execute de qualquer lugar
hashverify
```

### Método 3: Desenvolvimento

```bash
# Instale com ferramentas de desenvolvimento
pip install -e ".[dev]"

# Agora você tem acesso a:
# - black (formatação)
# - flake8, pylint (linting)
# - mypy (type checking)
# - pytest (testes)
```

## Uso Básico

### 1. Iniciar o Aplicativo

```bash
python -m hashverify
# ou
hashverify  # se instalado
```

### 2. Escanear uma Pasta

1. Clique em **"Procurar..."** na seção de configurações
2. Selecione a pasta que deseja verificar
3. Escolha o algoritmo de hash (MD5, SHA1 ou SHA256)
4. Clique em **"Iniciar Verificação"**

### 3. Visualizar Resultados

Os resultados aparecem na tabela com as seguintes colunas:
- **Arquivo**: Nome do arquivo
- **Caminho**: Localização completa
- **Hash**: Hash calculado
- **Detecções**: Status da análise (se API ativada)

### 4. Ações Disponíveis

**Duplo clique** em um arquivo: Abre no VirusTotal

**Clique direito** para:
- Copiar hash
- Verificar no VirusTotal
- Ver detalhes da análise
- Submeter arquivo ao VirusTotal
- Abrir localização do arquivo

## Configuração da API

### Obter API Key

1. Acesse [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Crie uma conta gratuita
3. Vá em **Perfil → API Key**
4. Copie sua chave

### Configurar no HashVerify

1. Marque **"Usar API VirusTotal"**
2. Cole sua API key no campo
3. (Opcional) Marque **"Mostrar"** para ver a key
4. Clique em **"Salvar"** para persistir
5. Clique em **"Testar API"** para validar

### Limites da API

**Conta Gratuita:**
- 4 requisições por minuto
- 500 requisições por dia

**Dica**: Ajuste "Solicitações/min" para respeitar seu limite

## Exportação de Relatórios

### Exportar para CSV

1. Após escanear arquivos
2. Clique em **"Exportar CSV"**
3. Escolha o local e nome do arquivo
4. O CSV incluirá todos os dados da análise

**Formato do CSV (com API):**
```csv
Nome,Caminho,Hash,Algoritmo,Link VirusTotal,Status,Detecções Maliciosas,Detecções Suspeitas,Total Engines
```

### Exportar para JSON

1. Clique em **"Exportar JSON"**
2. Escolha o local e nome
3. Formato estruturado para processamento automatizado

**Exemplo de JSON:**
```json
[
  {
    "filename": "exemplo.exe",
    "filepath": "/caminho/completo/exemplo.exe",
    "hash": "abc123...",
    "algorithm": "sha256",
    "vt_link": "https://virustotal.com/...",
    "status": "clean",
    "malicious_count": 0,
    "suspicious_count": 0,
    "total_engines": 75,
    "detection_ratio": "0/75",
    "detection_percentage": 0.0
  }
]
```

## Uso Avançado

### Verificação Seletiva

1. Execute um scan normal
2. Selecione arquivos específicos na tabela (Ctrl+Click)
3. Clique em **"Verificar Selecionados"**
4. Apenas os selecionados serão verificados no VT

### Submeter Arquivos Novos

Se um arquivo não foi encontrado no VirusTotal:

1. Clique direito no arquivo
2. Selecione **"Submeter Arquivo ao VirusTotal"**
3. Confirme o upload
4. Aguarde a análise (pode demorar alguns minutos)

**Nota**: Arquivos > 32MB não podem ser submetidos diretamente

### Interpretação dos Resultados

**Status de Detecção:**

- `✅ 0/75` - Limpo (0 detecções em 75 engines)
- `⚠️ 5/75` - Suspeito (5 detecções)
- `⚠️ 40/75` - Malicioso (muitas detecções)
- `Não encontrado` - Arquivo não está no VT
- `Pendente` - Aguardando consulta

**Cores:**
- 🟢 Verde: Limpo
- 🟠 Laranja: Suspeito
- 🔴 Vermelho: Malicioso

### Uso Programático

```python
from pathlib import Path
from hashverify.hash_calculator import HashCalculator, generate_vt_link
from hashverify.virustotal_api import VirusTotalAPI

# Calcular hash de um arquivo
calc = HashCalculator('sha256')
hash_value = calc.calculate_hash(Path('arquivo.exe'))
print(f"Hash: {hash_value}")

# Verificar no VirusTotal
api = VirusTotalAPI('sua-api-key')
result = api.check_hash(hash_value)
print(f"Detecções: {result}")
```

## Troubleshooting

### Erro: "API Key não definida"

**Solução**: Configure a API key nas configurações e clique em "Salvar"

### Erro: "Erro 401" ao testar API

**Solução**: API key inválida. Verifique se copiou corretamente

### Erro: "Erro 429" durante verificação

**Solução**: Limite de taxa excedido. Reduza "Solicitações/min" ou aguarde

### "Nenhum arquivo relevante encontrado"

**Solução**: A pasta não contém arquivos com as extensões suportadas:
- `.exe`, `.dll`, `.bat`, `.cmd`, `.msi`
- `.vbs`, `.ps1`, `.jar`, `.py`

### Interface não abre

**Problema**: tkinter não instalado

**Solução** (Linux):
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter
```

### Arquivo muito grande para upload

**Solução**: Arquivos > 32MB não podem ser submetidos via API.
Use a interface web do VirusTotal ou APIs premium.

## Dicas e Boas Práticas

1. **Use SHA256** - Mais seguro e amplamente suportado
2. **Salve relatórios** - Mantenha histórico em JSON/CSV
3. **Respeite limites** - Configure rate limit corretamente
4. **Verificação dupla** - Para arquivos suspeitos, verifique manualmente no site
5. **Cache inteligente** - O app guarda resultados para evitar consultas repetidas

## Suporte

- **Issues**: https://github.com/slashline15/hashverify/issues
- **Documentação**: https://github.com/slashline15/hashverify/wiki
- **Contribuir**: Veja CONTRIBUTING.md (quando disponível)
