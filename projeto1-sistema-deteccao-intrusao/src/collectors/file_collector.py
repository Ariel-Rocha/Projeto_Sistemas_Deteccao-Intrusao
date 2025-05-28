#!/usr/bin/env python3
"""
Coletor de logs de arquivos de texto.
Este módulo implementa funcionalidades para coletar logs de arquivos de texto comuns,
como logs de servidores web, logs de autenticação e logs de sistema.
"""

import os
import re
import gzip
import datetime
from pathlib import Path
from typing import List, Dict, Any, Generator, Optional, Union


class FileLogCollector:
    """
    Classe para coleta de logs de arquivos de texto.
    
    Esta classe fornece métodos para ler e processar logs de arquivos de texto,
    incluindo suporte para arquivos compactados e padrões de rotação comuns.
    """
    
    def __init__(self, log_path: str, pattern: Optional[str] = None):
        """
        Inicializa o coletor de logs de arquivo.
        
        Args:
            log_path: Caminho para o arquivo de log ou diretório contendo logs
            pattern: Padrão regex opcional para filtrar arquivos de log em um diretório
        """
        self.log_path = Path(log_path)
        self.pattern = pattern
        self.compiled_pattern = re.compile(pattern) if pattern else None
    
    def get_log_files(self) -> List[Path]:
        """
        Obtém a lista de arquivos de log disponíveis.
        
        Returns:
            Lista de caminhos para arquivos de log
        """
        if self.log_path.is_file():
            return [self.log_path]
        
        log_files = []
        for file in self.log_path.glob('*'):
            if file.is_file():
                if self.compiled_pattern and not self.compiled_pattern.search(file.name):
                    continue
                log_files.append(file)
        
        return sorted(log_files)
    
    def read_log_file(self, file_path: Path) -> Generator[str, None, None]:
        """
        Lê um arquivo de log linha por linha.
        
        Args:
            file_path: Caminho para o arquivo de log
            
        Yields:
            Cada linha do arquivo de log
        """
        if file_path.name.endswith('.gz'):
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line.rstrip('\n')
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line.rstrip('\n')
    
    def collect_logs(self, max_files: Optional[int] = None, 
                    start_time: Optional[datetime.datetime] = None,
                    end_time: Optional[datetime.datetime] = None) -> Generator[str, None, None]:
        """
        Coleta logs de todos os arquivos disponíveis.
        
        Args:
            max_files: Número máximo de arquivos a processar
            start_time: Hora de início para filtrar logs (não implementado)
            end_time: Hora de término para filtrar logs (não implementado)
            
        Yields:
            Cada linha de log dos arquivos processados
        """
        log_files = self.get_log_files()
        
        if max_files:
            log_files = log_files[:max_files]
        
        for file_path in log_files:
            for line in self.read_log_file(file_path):
                yield line


class ApacheLogCollector(FileLogCollector):
    """
    Coletor especializado para logs do servidor web Apache.
    """
    
    def __init__(self, log_path: str):
        """
        Inicializa o coletor de logs Apache.
        
        Args:
            log_path: Caminho para o arquivo de log ou diretório contendo logs Apache
        """
        super().__init__(log_path, pattern=r'access\.log.*')


class NginxLogCollector(FileLogCollector):
    """
    Coletor especializado para logs do servidor web Nginx.
    """
    
    def __init__(self, log_path: str):
        """
        Inicializa o coletor de logs Nginx.
        
        Args:
            log_path: Caminho para o arquivo de log ou diretório contendo logs Nginx
        """
        super().__init__(log_path, pattern=r'access\.log.*|error\.log.*')


class SSHLogCollector(FileLogCollector):
    """
    Coletor especializado para logs de autenticação SSH.
    """
    
    def __init__(self, log_path: str = "/var/log"):
        """
        Inicializa o coletor de logs SSH.
        
        Args:
            log_path: Caminho para o diretório de logs (padrão: /var/log)
        """
        super().__init__(log_path, pattern=r'auth\.log.*|secure.*')


if __name__ == "__main__":
    # Exemplo de uso
    import sys
    
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <caminho_para_logs>")
        sys.exit(1)
    
    log_path = sys.argv[1]
    collector = FileLogCollector(log_path)
    
    print(f"Coletando logs de: {log_path}")
    for i, line in enumerate(collector.collect_logs(max_files=1)):
        print(line)
        if i >= 9:  # Mostrar apenas as 10 primeiras linhas
            print("...")
            break
