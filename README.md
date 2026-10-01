# Aika C++ Server

Servidor do Aika em C++20 para Windows. Este diretório contém o código-fonte, o projeto CMake, um exemplo de configuração e um iniciador do executável.

## Requisitos

- Windows 10 ou 11, 64 bits.
- Visual Studio com a carga de trabalho **Desenvolvimento para desktop com C++** e MSVC x64.
- CMake 3.24 ou superior.
- MySQL 8, incluindo os arquivos de desenvolvimento do cliente C (`mysql.h`, `libmysql.lib`) e as DLLs necessárias para execução.
- Os arquivos de dados do servidor Aika e as definições NPC. Esses arquivos não fazem parte deste diretório.
- Um banco MySQL preparado com o schema compatível do servidor.

## Arquivos de dados necessários

Separe localmente os seguintes arquivos, obtidos da instalação de servidor que você tem autorização para usar:

```text
<Aika-Bin>/
  AikaServer.ini
  SL.bin
  Data/
    ItemList.bin
    SkillData.bin
    ExpList.bin
    ...

<NPCs>/
  *.npc
```

O carregamento também usa arquivos CSV e binários dentro de `Data`. Mantenha a estrutura original. Não coloque configurações com credenciais, dados de jogadores ou arquivos de jogo no Git.

## Compilar

Abra o **Developer PowerShell for Visual Studio** e execute a partir desta pasta. Ajuste os caminhos para a sua instalação:

```powershell
cmake -S . -B build -A x64 `
  -DMYSQL_ROOT="C:/Program Files/MySQL/MySQL Server 8.0" `
  -DAIKA_RUNTIME_ASSET_ROOT="D:/AikaServer/Bin" `
  -DAIKA_NPC_ASSET_ROOT="D:/AikaServer/NPCs"

cmake --build build --config Release --target aika_server
```

`MYSQL_ROOT` deve conter `include/mysql.h`, `lib/libmysql.lib`, `lib/libmysql.dll` e as DLLs OpenSSL usadas pelo cliente MySQL. O CMake copia as DLLs e os dados configurados para `build/Release`.

## Configurar o banco

Após compilar, abra `build/Release/AikaServer.ini` e configure os dados de conexão em `[MySQL]`. Use `config/AikaServer.example.ini` como referência; ele não contém credenciais válidas. O banco deve estar criado e conter o schema esperado pelo servidor. O executável inspeciona o schema no início, mas não cria nem migra automaticamente todas as tabelas.

Exemplo dos campos principais:

```ini
[Server]
Version=290
MAX_USERS=1000
Channels=1

[MySQL]
Server=127.0.0.1
Port=3306
Database=aika_db4
Username=aika_server
Password=COLOQUE_SUA_SENHA
UsernameGM=aika_server_gm
PasswordGM=COLOQUE_A_SENHA_GM
ServerGM=127.0.0.1
```

Crie usuários MySQL com as permissões necessárias para as tabelas usadas pelo servidor. Para desenvolvimento local, prefira uma conta dedicada com acesso apenas ao banco do Aika, em vez de usar `root`.

## Iniciar

Confirme que `build/Release` contém `AikaServer.ini`, `SL.bin`, `Data`, `NPCs` e as DLLs do MySQL. Execute:

```text
Iniciar-Aika-C++.cmd
```

O servidor grava `AikaServer.log` em `build/Release` e mantém uma janela de console aberta. Para encerrá-lo, use `Ctrl+C`. Também é possível iniciar diretamente:

```powershell
& .\build\Release\aika_server.exe (Resolve-Path .\build\Release).Path
```

O processo inicia os listeners HTTP/token na porta `8090`, login na porta `8831` e canais de jogo na porta `8822`. As entradas e endereços de canal anunciados ao cliente vêm de `SL.bin`; verifique se são alcançáveis pelo cliente e se o firewall permite as portas necessárias.

Se o servidor fechar ao iniciar, consulte o texto do console e as últimas linhas de `AikaServer.log`. As falhas mais comuns são caminho de dados incorreto, configuração MySQL inválida, schema ausente ou DLL de dependência não encontrada.

## Estado do projeto

O servidor C++ já inicializa, conecta ao MySQL e implementa partes de autenticação, entrada no mundo, movimentação, combate, NPCs e inventário. A migração ainda está em andamento: alguns sistemas do servidor Delphi e a equivalência completa do protocolo não foram concluídos. Revise e valide o comportamento no seu ambiente antes de usar este servidor em produção.

## Estrutura

```text
include/aika/   Interfaces C++
src/            Implementações do servidor
config/         Configuração de exemplo sem credenciais válidas
*.cmd           Iniciador do servidor no Windows
```

