#!/usr/bin/env python3
"""
Processador de logs para normalização e estruturação.
Este módulo implementa funcionalidades para processar logs brutos e convertê-los
em formatos estruturados para análise posterior.
"""

import re
import json
import datetime
from typing import Dict, Any, List, Optional, Union, Pattern


class LogParser:
    """
    Classe base para parsers de logs.
    
    Esta classe fornece métodos comuns para análise e normalização de logs
    de diferentes formatos.
    """
    
    def __init__(self):
        """Inicializa o parser de logs."""
        pass
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Analisa uma linha de log e retorna um dicionário estruturado.
        
        Args:
            line: Linha de log para analisar
            
        Returns:
            Dicionário com campos estruturados ou None se a linha não puder ser analisada
        """
        raise NotImplementedError("Subclasses devem implementar parse_line")
    
    def normalize_timestamp(self, timestamp_str: str, format_str: str) -> datetime.datetime:
        """
        Converte uma string de timestamp para um objeto datetime.
        
        Args:
            timestamp_str: String contendo o timestamp
            format_str: Formato do timestamp (conforme datetime.strptime)
            
        Returns:
            Objeto datetime normalizado
        """
        try:
            return datetime.datetime.strptime(timestamp_str, format_str)
        except ValueError:
            # Fallback para o timestamp atual se não for possível analisar
            return datetime.datetime.now()


class ApacheLogParser(LogParser):
    """
    Parser para logs do servidor web Apache no formato Common Log Format (CLF)
    ou Combined Log Format.
    """
    
    def __init__(self):
        """Inicializa o parser de logs Apache."""
        super().__init__()
        # Regex para Common Log Format e Combined Log Format
        self.log_pattern = re.compile(
            r'(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"'
        )
        self.simple_log_pattern = re.compile(
            r'(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\S+)'
        )
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Analisa uma linha de log do Apache.
        
        Args:
            line: Linha de log do Apache
            
        Returns:
            Dicionário com campos estruturados ou None se a linha não puder ser analisada
        """
        match = self.log_pattern.match(line)
        if match:
            return {
                'ip': match.group(1),
                'identity': match.group(2),
                'user': match.group(3),
                'timestamp': self.normalize_timestamp(match.group(4), '%d/%b/%Y:%H:%M:%S %z'),
                'method': match.group(5),
                'path': match.group(6),
                'protocol': match.group(7),
                'status': int(match.group(8)),
                'size': match.group(9) if match.group(9) != '-' else 0,
                'referer': match.group(10),
                'user_agent': match.group(11),
                'raw': line
            }
        
        # Tenta o formato mais simples
        match = self.simple_log_pattern.match(line)
        if match:
            return {
                'ip': match.group(1),
                'identity': match.group(2),
                'user': match.group(3),
                'timestamp': self.normalize_timestamp(match.group(4), '%d/%b/%Y:%H:%M:%S %z'),
                'method': match.group(5),
                'path': match.group(6),
                'protocol': match.group(7),
                'status': int(match.group(8)),
                'size': match.group(9) if match.group(9) != '-' else 0,
                'referer': '-',
                'user_agent': '-',
                'raw': line
            }
        
        return None


class SSHLogParser(LogParser):
    """
    Parser para logs de autenticação SSH.
    """
    
    def __init__(self):
        """Inicializa o parser de logs SSH."""
        super().__init__()
        # Padrões para diferentes tipos de mensagens SSH
        self.patterns = {
            'failed_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Failed password for (\S+) from (\S+) port (\d+)'
            ),
            'accepted_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Accepted password for (\S+) from (\S+) port (\d+)'
            ),
            'invalid_user': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Invalid user (\S+) from (\S+) port (\d+)'
            )
        }
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Analisa uma linha de log SSH.
        
        Args:
            line: Linha de log SSH
            
        Returns:
            Dicionário com campos estruturados ou None se a linha não puder ser analisada
        """
        # Corrigido: Verificar primeiro o padrão de "Invalid user"
        match = self.patterns['invalid_user'].match(line)
        if match:
            return {
                'timestamp': self.normalize_timestamp(match.group(1), '%b %d %H:%M:%S'),
                'event_type': 'invalid_user',
                'user': match.group(2),
                'source_ip': match.group(3),
                'port': int(match.group(4)),
                'raw': line
            }
            
        # Verificar outros padrões
        for event_type, pattern in self.patterns.items():
            if event_type == 'invalid_user':
                continue  # Já verificado acima
                
            match = pattern.match(line)
            if match:
                return {
                    'timestamp': self.normalize_timestamp(match.group(1), '%b %d %H:%M:%S'),
                    'event_type': event_type,
                    'user': match.group(2),
                    'source_ip': match.group(3),
                    'port': int(match.group(4)),
                    'raw': line
                }
        
        # Verificar se é uma tentativa de login SSH genérica
        if 'sshd' in line and ('Failed' in line or 'Accepted' in line or 'Invalid' in line):
            return {
                'timestamp': datetime.datetime.now(),  # Fallback quando não conseguimos extrair o timestamp
                'event_type': 'ssh_auth_event',
                'raw': line
            }
        
        return None


class LogNormalizer:
    """
    Classe para normalizar logs de diferentes formatos em uma estrutura comum.
    """
    
    def __init__(self):
        """Inicializa o normalizador de logs."""
        self.parsers = {
            'apache': ApacheLogParser(),
            'ssh': SSHLogParser(),
            # Outros parsers podem ser adicionados aqui
        }
    
    def normalize(self, line: str, log_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Normaliza uma linha de log usando o parser apropriado.
        
        Args:
            line: Linha de log para normalizar
            log_type: Tipo de log (apache, ssh, etc.) ou None para auto-detecção
            
        Returns:
            Dicionário normalizado ou None se a linha não puder ser analisada
        """
        if log_type and log_type in self.parsers:
            return self.parsers[log_type].parse_line(line)
        
        # Auto-detecção do tipo de log
        for parser_type, parser in self.parsers.items():
            result = parser.parse_line(line)
            if result:
                result['log_type'] = parser_type
                return result
        
        # Fallback para log não reconhecido
        return {
            'timestamp': datetime.datetime.now(),
            'log_type': 'unknown',
            'raw': line
        }


if __name__ == "__main__":
    # Exemplo de uso
    normalizer = LogNormalizer()
    
    # Exemplo de log Apache
    apache_log = '192.168.1.100 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/start.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    result = normalizer.normalize(apache_log)
    print(json.dumps(result, default=str, indent=2))
    
    # Exemplo de log SSH
    ssh_log = 'May 15 23:45:12 server sshd[12345]: Failed password for invalid user admin from 203.0.113.100 port 22 ssh2'
    result = normalizer.normalize(ssh_log)
    print(json.dumps(result, default=str, indent=2))
