# 🔐 HashVerify - Verificador de Segurança de Arquivos


Uma aplicação em Python com interface gráfica (Tkinter) para calcular hashes de arquivos e verificar possíveis ameaças usando a API do [VirusTotal](https://www.virustotal.com/). Ideal para validar arquivos `.exe`, `.dll`, `.bat`, `.ps1`, entre outros, com facilidade e exportar relatórios profissionais em CSV e JSON. Ou simplesmente, verificar os calcular os hashs de arquivos uma pasta e receber a lista de links para a verificação manual.

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
  - `requests`
  - `tkinter` (incluso na maioria dos Pythons)
  - `hashlib`, `os`, `threading`, `json`, `csv`, etc. (nativos)

Instale o `requests` se necessário:

```bash
pip install requests
```

## 🚀 Como usar

1. Clone o repositório:

```bash
git clone https://github.com/seu-usuario/hashverify.git
cd hashverify
```

2. Execute o script:

```bash
python hashverify.py
```

Ou se quiser algo mais prático, só baixe o `verifica_hash.py` e execute e execute com um `.cmd` simples:

```bash
@echo off
python "C:\local\do\arquivo\verifica_hash.py" %1
pause
```


3. Se quiser usar o VirusTotal:

   * Marque a opção `Usar API VirusTotal`
   * Cole sua chave de API (você pode obter uma gratuitamente no [site oficial](https://www.virustotal.com/gui/join-us))
   * Teste a conexão clicando em "Testar API"

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

## 🛠 Autor

Desenvolvido por [@slashline15](https://github.com/slashline15) — engenheiro civil, hacker de produtividade e automação.

---

## 📄 Licença

MIT. Faça bom uso e contribua se quiser. Não me culpe se você subir um trojan por engano 😅.
