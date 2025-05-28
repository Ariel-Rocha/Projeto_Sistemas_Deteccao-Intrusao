# Dados Brutos (Raw)

Este diretório armazena os dados brutos coletados pelo Sistema de Detecção de Intrusão.

## Propósito

Os dados brutos representam as informações coletadas diretamente das fontes, sem qualquer processamento, normalização ou transformação. Manter esses dados em seu formato original é essencial para:

- Preservar a integridade da informação original
- Permitir reprocessamento em caso de mudanças nos algoritmos
- Servir como evidência forense em investigações de segurança
- Possibilitar auditoria e rastreabilidade

## Tipos de Dados Armazenados

- Logs de servidores web (Apache, Nginx)
- Logs de autenticação SSH
- Logs de firewall
- Logs de sistemas operacionais
- Capturas de tráfego de rede
- Logs de aplicações

## Formato de Armazenamento

Os dados são armazenados seguindo a convenção de nomenclatura:
```
{fonte}_{tipo}_{data}_{hora}.log
```

Exemplos:
- `webserver1_apache_20250515_120000.log`
- `firewall_connection_20250515_120000.log`
- `auth_ssh_20250515_120000.log`

## Retenção de Dados

Por padrão, os dados brutos são mantidos por 90 dias antes de serem arquivados ou excluídos, conforme políticas de retenção. Dados relacionados a incidentes de segurança podem ser preservados por períodos mais longos.
