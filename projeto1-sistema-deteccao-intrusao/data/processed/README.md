# Dados Processados

Este diretório armazena os dados após processamento pelo Sistema de Detecção de Intrusão.

## Propósito

Os dados processados são o resultado da normalização, limpeza e transformação dos dados brutos. Este processamento é essencial para:

- Padronizar formatos de diferentes fontes
- Enriquecer dados com informações contextuais
- Estruturar dados para análise eficiente
- Remover informações redundantes ou irrelevantes
- Preparar dados para algoritmos de detecção de anomalias

## Estrutura de Dados Processados

Os dados processados são armazenados em formatos estruturados como:
- JSON: Para flexibilidade e compatibilidade com diversas ferramentas
- CSV: Para análises estatísticas e compatibilidade com ferramentas de planilha
- Parquet: Para análises de grande volume com eficiência de armazenamento

## Organização

Os dados são organizados por:
- Tipo de log (web, auth, firewall)
- Período de tempo (dia, semana, mês)
- Criticidade (alta, média, baixa)

## Metadados

Cada conjunto de dados processados inclui metadados que registram:
- Fonte original dos dados
- Timestamp do processamento
- Versão do processador utilizado
- Transformações aplicadas
- Estatísticas básicas (contagens, médias, etc.)

## Exemplo de Estrutura de Dados Processados

```json
{
  "metadata": {
    "source": "webserver1_apache_20250515_120000.log",
    "processed_at": "2025-05-15T12:30:00Z",
    "processor_version": "1.2.3",
    "record_count": 1500
  },
  "records": [
    {
      "timestamp": "2025-05-15T12:00:01Z",
      "source_ip": "192.168.1.100",
      "method": "GET",
      "path": "/admin",
      "status_code": 403,
      "user_agent": "Mozilla/5.0...",
      "risk_score": 0.75
    },
    // Mais registros...
  ]
}
```
