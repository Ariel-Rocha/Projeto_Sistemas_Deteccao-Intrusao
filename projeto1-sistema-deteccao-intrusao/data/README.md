# Diretório de Dados

Este diretório armazena os dados utilizados pelo Sistema de Detecção de Intrusão.

## Propósito

O diretório de dados é organizado para separar dados brutos (raw) de dados processados, seguindo as melhores práticas de engenharia de dados. Esta estrutura facilita o rastreamento da origem dos dados e as transformações aplicadas.

## Estrutura

- **raw/**: Dados brutos coletados de diversas fontes antes de qualquer processamento
- **processed/**: Dados após normalização, limpeza e transformação
- **reports/**: Relatórios e resultados de análises gerados pelo sistema

## Fluxo de Dados

1. Os coletores de logs obtêm dados brutos de várias fontes (servidores, firewalls, etc.)
2. Os dados brutos são armazenados no diretório `raw/` com metadados de origem
3. Os processadores normalizam e estruturam os dados, salvando-os em `processed/`
4. Os analisadores detectam anomalias e geram alertas baseados nos dados processados
5. Os relatórios e resultados são salvos no diretório `reports/`

## Considerações de Segurança

- Os dados podem conter informações sensíveis e devem ser protegidos adequadamente
- Considere implementar criptografia para dados em repouso
- Defina políticas de retenção de dados para conformidade com regulamentações
