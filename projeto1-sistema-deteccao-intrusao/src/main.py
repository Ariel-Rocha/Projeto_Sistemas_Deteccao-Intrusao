#!/usr/bin/env python3
"""
Módulo principal do Sistema de Detecção de Intrusão com Análise de Logs.
Este script integra os diferentes componentes do sistema para fornecer
uma solução completa de detecção de intrusões baseada em análise de logs.
"""

import os
import sys
import argparse
import logging
import json
import datetime
from typing import Dict, List, Any, Optional

# Importar módulos do projeto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.collectors.file_collector import FileLogCollector, ApacheLogCollector, SSHLogCollector
from src.processors.log_parser import LogNormalizer
from src.analyzers.log_analyzer import BruteForceDetector, AnomalyDetector
from src.alerting.alert_manager import Alert, AlertManager


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """
    Configura o sistema de logging.
    
    Args:
        log_level: Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Objeto logger configurado
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('intrusion_detection.log')
        ]
    )
    return logging.getLogger("IntrusionDetection")


def parse_arguments():
    """
    Analisa os argumentos da linha de comando.
    
    Returns:
        Objeto com os argumentos analisados
    """
    parser = argparse.ArgumentParser(description='Sistema de Detecção de Intrusão com Análise de Logs')
    
    parser.add_argument('--log-dir', type=str, default='/var/log',
                        help='Diretório contendo os arquivos de log')
    parser.add_argument('--log-type', type=str, choices=['apache', 'nginx', 'ssh', 'auto'],
                        default='auto', help='Tipo de log a ser analisado')
    parser.add_argument('--output', type=str, default='alerts.json',
                        help='Arquivo de saída para alertas')
    parser.add_argument('--threshold', type=int, default=5,
                        help='Limiar para detecção de força bruta')
    parser.add_argument('--time-window', type=int, default=300,
                        help='Janela de tempo (segundos) para detecção de força bruta')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Nível de logging')
    parser.add_argument('--max-logs', type=int, default=1000,
                        help='Número máximo de logs a processar')
    
    return parser.parse_args()


def collect_logs(args) -> List[str]:
    """
    Coleta logs com base nos argumentos fornecidos.
    
    Args:
        args: Argumentos da linha de comando
        
    Returns:
        Lista de linhas de log coletadas
    """
    logger = logging.getLogger("LogCollector")
    logger.info(f"Coletando logs do diretório: {args.log_dir}")
    
    # Selecionar o coletor apropriado
    if args.log_type == 'apache':
        collector = ApacheLogCollector(args.log_dir)
    elif args.log_type == 'nginx':
        collector = FileLogCollector(args.log_dir, pattern=r'access\.log.*|error\.log.*')
    elif args.log_type == 'ssh':
        collector = SSHLogCollector(args.log_dir)
    else:  # auto
        collector = FileLogCollector(args.log_dir)
    
    # Coletar logs
    logs = []
    for i, line in enumerate(collector.collect_logs()):
        logs.append(line)
        if args.max_logs and i >= args.max_logs:
            break
    
    logger.info(f"Coletados {len(logs)} logs")
    return logs


def process_logs(raw_logs: List[str], log_type: str) -> List[Dict[str, Any]]:
    """
    Processa e normaliza logs brutos.
    
    Args:
        raw_logs: Lista de linhas de log brutas
        log_type: Tipo de log ou 'auto' para detecção automática
        
    Returns:
        Lista de logs normalizados
    """
    logger = logging.getLogger("LogProcessor")
    logger.info("Processando logs...")
    
    normalizer = LogNormalizer()
    normalized_logs = []
    
    for line in raw_logs:
        if not line.strip():
            continue
            
        result = normalizer.normalize(line, log_type if log_type != 'auto' else None)
        if result:
            normalized_logs.append(result)
    
    logger.info(f"Normalizados {len(normalized_logs)} logs")
    return normalized_logs


def analyze_logs(normalized_logs: List[Dict[str, Any]], args) -> List[Dict[str, Any]]:
    """
    Analisa logs normalizados para detectar atividades suspeitas.
    
    Args:
        normalized_logs: Lista de logs normalizados
        args: Argumentos da linha de comando
        
    Returns:
        Lista de alertas gerados
    """
    logger = logging.getLogger("LogAnalyzer")
    logger.info("Analisando logs...")
    
    # Agrupar logs por tipo
    logs_by_type = {}
    for log in normalized_logs:
        log_type = log.get('log_type', 'unknown')
        if log_type not in logs_by_type:
            logs_by_type[log_type] = []
        logs_by_type[log_type].append(log)
    
    # Aplicar detectores apropriados para cada tipo de log
    all_alerts = []
    
    # Detector de força bruta para logs SSH
    if 'ssh' in logs_by_type:
        logger.info(f"Analisando {len(logs_by_type['ssh'])} logs SSH para detecção de força bruta")
        brute_detector = BruteForceDetector(
            threshold=args.threshold,
            time_window=args.time_window
        )
        alerts = brute_detector.analyze(logs_by_type['ssh'])
        all_alerts.extend(alerts)
        logger.info(f"Detectados {len(alerts)} alertas de força bruta")
    
    # Detector de anomalias para logs web
    if 'apache' in logs_by_type:
        logger.info(f"Analisando {len(logs_by_type['apache'])} logs Apache para detecção de anomalias")
        anomaly_detector = AnomalyDetector(contamination=0.05)
        
        # Treinar com uma parte dos logs
        train_size = min(len(logs_by_type['apache']), 500)
        anomaly_detector.train(logs_by_type['apache'][:train_size])
        
        # Analisar todos os logs
        alerts = anomaly_detector.analyze(logs_by_type['apache'])
        all_alerts.extend(alerts)
        logger.info(f"Detectados {len(alerts)} alertas de anomalias")
    
    return all_alerts


def main():
    """Função principal do sistema."""
    # Analisar argumentos
    args = parse_arguments()
    
    # Configurar logging
    logger = setup_logging(args.log_level)
    logger.info("Iniciando Sistema de Detecção de Intrusão")
    
    try:
        # Coletar logs
        raw_logs = collect_logs(args)
        
        # Processar logs
        normalized_logs = process_logs(raw_logs, args.log_type)
        
        # Analisar logs
        alerts = analyze_logs(normalized_logs, args)
        
        # Gerenciar alertas
        alert_manager = AlertManager()
        for alert_data in alerts:
            alert = Alert(
                alert_type=alert_data.get('alert_type', 'unknown'),
                severity=alert_data.get('severity', 'medium'),
                details=alert_data.get('details', ''),
                timestamp=alert_data.get('timestamp'),
                source_ip=alert_data.get('source_ip'),
                raw_logs=alert_data.get('raw_logs', [])
            )
            alert_manager.add_alert(alert)
        
        # Salvar alertas
        alert_manager.save_alerts(args.output)
        logger.info(f"Salvos {len(alerts)} alertas em {args.output}")
        
        # Resumo
        print(f"\nResumo da Análise:")
        print(f"- Logs processados: {len(normalized_logs)}")
        print(f"- Alertas gerados: {len(alerts)}")
        
        severity_counts = {}
        for alert_data in alerts:
            severity = alert_data.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            print(f"  - {severity.capitalize()}: {count}")
        
        print(f"\nOs alertas foram salvos em: {args.output}")
        
    except Exception as e:
        logger.error(f"Erro durante a execução: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
