# Diretório de Configuração

Este diretório contém arquivos de configuração para o Sistema de Detecção de Intrusão.

## Propósito

Os arquivos de configuração permitem personalizar o comportamento do sistema sem modificar o código-fonte. Isso facilita a adaptação do sistema para diferentes ambientes (desenvolvimento, teste, produção) e casos de uso.

## Arquivos de Configuração

- `config.yaml`: Configuração principal do sistema
- `logging.yaml`: Configuração de logs e níveis de verbosidade
- `rules.yaml`: Regras de detecção personalizadas

## Exemplo de Uso

```python
import yaml

# Carregar configuração
with open('config/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Acessar valores de configuração
log_level = config['logging']['level']
detection_threshold = config['detection']['threshold']
```

## Estrutura de Configuração

A configuração segue uma estrutura hierárquica para organizar as diferentes opções:

- **logging**: Configurações relacionadas a logs
- **detection**: Parâmetros para algoritmos de detecção
- **collectors**: Configuração de fontes de dados
- **alerting**: Configuração de notificações e alertas
