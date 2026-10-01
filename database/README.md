# Schema do banco

O servidor espera um banco MySQL com o schema compatível da source Delphi. A
versão C++ inspeciona as tabelas no boot, mas não cria nem migra automaticamente
todas elas.

O dump do banco local não acompanha a Release: ele pode conter contas, hashes de
senha, tokens e personagens. Para distribuição pública, use um dump somente de
estrutura, sem linhas de dados. Esse arquivo ainda precisa ser exportado do
MySQL local antes de ser adicionado como `aika_db4_schema.sql`.

## Exportar somente a estrutura

Com `mysqldump` instalado, execute no PowerShell, ajustando host, usuário e nome
do banco. A opção `--password` solicita a senha no prompt, sem colocá-la no
comando ou no arquivo exportado.

```powershell
mysqldump --host=127.0.0.1 --port=3306 --user=SEU_USUARIO --password `
  --no-data --routines --triggers aika_db4 `
  --result-file=database/aika_db4_schema.sql
```

Antes de publicar, confirme que o arquivo não contém `INSERT INTO` nem dados de
contas/personagens. Não substitua esse dump por um backup completo do banco.

## Importar

Crie um banco vazio e carregue o SQL de estrutura com MySQL Workbench ou `mysql`.
Depois configure `AikaServer.ini` para apontar para esse banco e crie as contas
de jogo necessárias no seu ambiente.
