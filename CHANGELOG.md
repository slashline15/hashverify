# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [2.0.0] - 2025-01-XX

### 🎉 Refatoração Completa - Foco em Qualidade de Código

### Added
- **Arquitetura Modular**: Código organizado em módulos especializados
  - `config.py`: Gerenciamento de configurações
  - `models.py`: Modelos de dados com dataclasses
  - `hash_calculator.py`: Lógica de cálculo de hashes
  - `virustotal_api.py`: Cliente da API do VirusTotal
  - `gui.py`: Interface gráfica refatorada
- **Type Hints**: Tipagem completa em todas as funções e métodos
- **Docstrings**: Documentação Google-style em todas as classes e funções
- **pyproject.toml**: Configuração moderna do projeto com:
  - Configurações de Black, isort, mypy, pylint, flake8
  - Metadados do pacote
  - Scripts de instalação
- **requirements.txt**: Gerenciamento claro de dependências
- **.gitignore**: Arquivo completo para projetos Python
- **CHANGELOG.md**: Documentação de mudanças
- Estrutura de pastas profissional (src/, tests/, docs/)
- Suporte a instalação via `pip install -e .`
- Comando CLI após instalação: `hashverify`

### Changed
- Interface gráfica completamente refatorada com melhor organização
- Melhor separação de responsabilidades entre módulos
- ConfigManager para gerenciar configurações de forma centralizada
- Modelos de dados usando dataclasses para maior clareza
- HashCalculator como classe especializada
- VirusTotalAPI como cliente dedicado com cache e rate limiting
- README.md atualizado com novas instruções e badges

### Improved
- Código mais legível e manutenível
- Melhor tratamento de erros
- Tipagem forte para detectar erros em tempo de desenvolvimento
- Documentação inline completa
- Preparado para testes unitários (estrutura criada)
- Compatibilidade mantida com script legado (`verifica_hash.py`)

## [1.0.0] - 2024-XX-XX

### Added
- Interface gráfica inicial com Tkinter
- Cálculo de hashes (MD5, SHA1, SHA256)
- Integração com API do VirusTotal
- Exportação de relatórios em CSV e JSON
- Cache de resultados
- Limite de taxa de requisições
- Menu de contexto com ações
- Submissão de arquivos ao VirusTotal
- Testes de API
- Configuração persistente
