# 🔐 HashVerify - Verificador de Segurança de Arquivos

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Uma aplicação em Python com interface gráfica (Tkinter) para calcular hashes de arquivos e verificar possíveis ameaças usando a API do [VirusTotal](https://www.virustotal.com/). Ideal para validar arquivos `.exe`, `.dll`, `.bat`, `.ps1`, entre outros, com facilidade e exportar relatórios profissionais em CSV e JSON.

**Versão 2.0**: Código completamente refatorado com arquitetura modular, type hints, docstrings completas e práticas profissionais de desenvolvimento.

---

## ✨ Funcionalidades

- 📁 Seleção de pasta para escanear arquivos automaticamente
- 🔐 Suporte a múltiplos algoritmos de hash (`md5`, `sha1`, `sha256`)
- 🛡️ Integração opcional com a API do VirusTotal
  - Detecção automática de malware/suspicious
  - Consulta e submissão de arquivos diretamente pela interface
- 📊 Exportação de resultados em **CSV** e **JSON**
- 💡 Interface simples, intuitiva e leve
- ✅ Detecção visual com barra de progresso e feedback colorido
- 📌 Suporte a cache de resultados para evitar consultas repetidas
- 🧪 Teste de API integrada

---

## 🧪 Requisitos

- Python 3.7+
- Bibliotecas:
  - `requests` (para API do VirusTotal)
  - `tkinter` (incluso na maioria das instalações Python)
  - Bibliotecas padrão: `hashlib`, `pathlib`, `threading`, `json`, `csv`, etc.

### Instalação de Dependências

```bash
# Instalação básica
pip install -r requirements.txt

# Ou instalação via pyproject.toml
pip install -e .

# Com ferramentas de desenvolvimento
pip install -e ".[dev]"
```

## 🚀 Como usar

### Instalação

1. Clone o repositório:

```bash
git clone https://github.com/slashline15/hashverify.git
cd hashverify
```

2. Instale as dependências:

```bash
pip install -r requirements.txt
```

### Execução

**Método 1: Como módulo Python**
```bash
python -m hashverify
```

**Método 2: Diretamente pelo script**
```bash
python src/hashverify/gui.py
```

**Método 3: Via script legado (compatibilidade)**
```bash
python verifica_hash.py
```

**Método 4: Após instalar o pacote**
```bash
pip install -e .
hashverify
```

### Configuração do VirusTotal

1. Marque a opção `Usar API VirusTotal`
2. Cole sua chave de API (obtenha gratuitamente no [site oficial](https://www.virustotal.com/gui/join-us))
3. Teste a conexão clicando em "Testar API"
4. Ajuste o limite de requisições/minuto conforme seu plano

---

## 🧠 Como funciona

* O programa varre a pasta escolhida e calcula o hash dos arquivos com extensões relevantes.
* Com a API ativa, ele consulta cada hash no VirusTotal e exibe os resultados.
* Os resultados podem ser exportados em **CSV** ou **JSON**, incluindo:

  * Nome, caminho, hash, link direto para o VT
  * Número de detecções, status (malicioso, suspeito, limpo)

---

## 📁 Extensões verificadas

* `.exe`, `.dll`, `.bat`, `.cmd`, `.msi`, `.vbs`, `.ps1`, `.jar`, `.py`

---

## ⚠️ Observações

* Arquivos acima de 32MB **não podem ser submetidos diretamente** ao VirusTotal.
* Resultados de análise são públicos no VirusTotal após submissão.
* Há controle de taxa (requests/minuto) configurável para respeitar limites da sua API key.

---

## 📷 Exemplo de uso

### Interface principal:

![HashVerify Interface](https://github.com/user-attachments/assets/7d9da1d2-d202-4599-9a45-905dfe076fcf)

---

## 📂 Estrutura do Projeto

```
hashverify/
├── src/
│   └── hashverify/
│       ├── __init__.py          # Módulo principal
│       ├── __main__.py          # Entry point
│       ├── config.py            # Configurações e constantes
│       ├── models.py            # Modelos de dados (dataclasses)
│       ├── hash_calculator.py   # Lógica de cálculo de hash
│       ├── virustotal_api.py    # Cliente da API do VirusTotal
│       └── gui.py               # Interface gráfica
├── tests/                       # Testes unitários (a implementar)
├── docs/                        # Documentação adicional
├── verifica_hash.py             # Script legado (compatibilidade)
├── requirements.txt             # Dependências
├── pyproject.toml              # Configuração do projeto e ferramentas
├── .gitignore                  # Arquivos ignorados pelo git
└── README.md                   # Este arquivo
```

---

## 🎨 Qualidade de Código

### Melhorias da Versão 2.0

✅ **Arquitetura Modular**: Código separado em módulos especializados
✅ **Type Hints**: Tipagem completa em todas as funções e métodos
✅ **Docstrings**: Documentação Google-style em todas as classes e funções
✅ **Configuração de Linting**: Black, Flake8, Pylint, Mypy configurados
✅ **Gerenciamento de Dependências**: requirements.txt e pyproject.toml
✅ **Padrões Profissionais**: PEP 8, configurações de CI/CD prontas

### Ferramentas de Desenvolvimento

```bash
# Formatação automática
black src/

# Verificação de estilo
flake8 src/

# Linting completo
pylint src/hashverify/

# Type checking
mypy src/hashverify/

# Ordenação de imports
isort src/

# Executar todos de uma vez
black src/ && isort src/ && flake8 src/ && mypy src/hashverify/
```

### Executando Testes

```bash
# Instalar dependências de dev
pip install -e ".[dev]"

# Executar testes (quando implementados)
pytest

# Com cobertura
pytest --cov=hashverify --cov-report=html
```

---

## 🛠 Autor

Desenvolvido por [@slashline15](https://github.com/slashline15) — engenheiro civil, hacker de produtividade e automação.

**Versão 2.0** refatorada com foco em qualidade de código e manutenibilidade.

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

Certifique-se de que o código segue os padrões:
- Executar `black` e `isort` antes de commitar
- Passar em `flake8` e `mypy`
- Adicionar docstrings em novas funções/classes

---

## 📄 Licença

MIT. Faça bom uso e contribua se quiser. Não me culpe se você subir um trojan por engano 😅.
