#!/usr/bin/env python3
"""
Script de integração para o Sistema de Detecção de Intrusão.
Este script executa um teste de integração completo do sistema.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Adicionar o diretório raiz ao path para importação dos módulos
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.collectors.file_collector import FileLogCollector
from src.processors.log_parser import LogNormalizer
from src.analyzers.log_analyzer import BruteForceDetector, AnomalyDetector
from src.alerting.alert_manager import Alert, AlertManager


def setup_test_environment():
    """
    Configura o ambiente de teste com arquivos de log simulados.
    
    Returns:
        Tuple contendo o diretório temporário e os caminhos para os arquivos de log
    """
    print("Configurando ambiente de teste...")
    
    # Criar diretório temporário
    temp_dir = tempfile.mkdtemp()
    
    # Criar arquivos de log simulados
    apache_log_path = os.path.join(temp_dir, "apache_access.log")
    ssh_log_path = os.path.join(temp_dir, "ssh_auth.log")
    
    # Logs Apache simulados
    with open(apache_log_path, 'w') as f:
        f.write('192.168.1.100 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/start.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n')
        f.write('192.168.1.101 - - [10/Oct/2023:13:56:12 -0700] "GET /about.html HTTP/1.1" 200 1854 "http://example.com/index.html" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"\n')
        f.write('192.168.1.102 - - [10/Oct/2023:13:57:45 -0700] "GET /images/logo.png HTTP/1.1" 200 4582 "http://example.com/index.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n')
        f.write('10.0.0.1 - - [10/Oct/2023:14:02:22 -0700] "GET /admin.php HTTP/1.1" 404 521 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"\n')
        f.write('10.0.0.1 - - [10/Oct/2023:14:02:25 -0700] "GET /wp-login.php HTTP/1.1" 404 521 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"\n')
        f.write('10.0.0.1 - - [10/Oct/2023:14:02:28 -0700] "GET /phpmyadmin HTTP/1.1" 404 521 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"\n')
        f.write('10.0.0.1 - - [10/Oct/2023:14:02:30 -0700] "GET /?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 2326 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"\n')
    
    # Logs SSH simulados
    with open(ssh_log_path, 'w') as f:
        f.write('Oct 10 14:10:22 server sshd[12345]: Accepted password for john from 192.168.1.200 port 48252\n')
        f.write('Oct 10 14:15:36 server sshd[12346]: Failed password for invalid user root from 10.0.0.2 port 52413\n')
        f.write('Oct 10 14:15:48 server sshd[12346]: Failed password for invalid user root from 10.0.0.2 port 52414\n')
        f.write('Oct 10 14:16:02 server sshd[12346]: Failed password for invalid user root from 10.0.0.2 port 52415\n')
        f.write('Oct 10 14:16:15 server sshd[12346]: Failed password for invalid user admin from 10.0.0.2 port 52416\n')
        f.write('Oct 10 14:16:30 server sshd[12346]: Failed password for invalid user admin from 10.0.0.2 port 52417\n')
        f.write('Oct 10 14:16:45 server sshd[12346]: Failed password for invalid user admin from 10.0.0.2 port 52418\n')
        f.write('Oct 10 14:20:12 server sshd[12347]: Accepted password for alice from 192.168.1.201 port 48512\n')
    
    return temp_dir, apache_log_path, ssh_log_path


def run_integration_test(apache_log_path, ssh_log_path):
    """
    Executa um teste de integração completo do sistema.
    
    Args:
        apache_log_path: Caminho para o arquivo de logs Apache
        ssh_log_path: Caminho para o arquivo de logs SSH
        
    Returns:
        Dicionário com os resultados do teste
    """
    print("Executando teste de integração...")
    
    # Etapa 1: Coleta de logs
    print("Etapa 1: Coleta de logs")
    apache_collector = FileLogCollector(apache_log_path)
    ssh_collector = FileLogCollector(ssh_log_path)
    
    apache_logs = list(apache_collector.collect_logs())
    ssh_logs = list(ssh_collector.collect_logs())
    
    print(f"  - Coletados {len(apache_logs)} logs Apache")
    print(f"  - Coletados {len(ssh_logs)} logs SSH")
    
    # Etapa 2: Processamento e normalização
    print("Etapa 2: Processamento e normalização")
    normalizer = LogNormalizer()
    
    normalized_apache_logs = []
    for line in apache_logs:
        result = normalizer.normalize(line, 'apache')
        if result:
            normalized_apache_logs.append(result)
    
    normalized_ssh_logs = []
    for line in ssh_logs:
        result = normalizer.normalize(line, 'ssh')
        if result:
            normalized_ssh_logs.append(result)
    
    print(f"  - Normalizados {len(normalized_apache_logs)} logs Apache")
    print(f"  - Normalizados {len(normalized_ssh_logs)} logs SSH")
    
    # Etapa 3: Análise de logs
    print("Etapa 3: Análise de logs")
    brute_detector = BruteForceDetector(threshold=3, time_window=600)
    anomaly_detector = AnomalyDetector(contamination=0.2)
    
    # Treinar detector de anomalias
    if normalized_apache_logs:
        anomaly_detector.train(normalized_apache_logs)
    
    # Detectar ataques de força bruta
    brute_alerts = brute_detector.analyze(normalized_ssh_logs)
    print(f"  - Detectados {len(brute_alerts)} alertas de força bruta")
    
    # Detectar anomalias
    anomaly_alerts = anomaly_detector.analyze(normalized_apache_logs)
    print(f"  - Detectados {len(anomaly_alerts)} alertas de anomalias")
    
    # Etapa 4: Gerenciamento de alertas
    print("Etapa 4: Gerenciamento de alertas")
    alert_manager = AlertManager()
    
    # Adicionar alertas ao gerenciador
    for alert_data in brute_alerts + anomaly_alerts:
        alert = Alert(
            alert_type=alert_data.get('alert_type', 'unknown'),
            severity=alert_data.get('severity', 'medium'),
            details=alert_data.get('details', ''),
            timestamp=alert_data.get('timestamp'),
            source_ip=alert_data.get('source_ip'),
            raw_logs=alert_data.get('raw_logs', [])
        )
        alert_manager.add_alert(alert)
    
    # Filtrar alertas por severidade
    high_alerts = alert_manager.get_alerts(severity="high")
    medium_alerts = alert_manager.get_alerts(severity="medium")
    
    print(f"  - Total de alertas: {len(alert_manager.alerts)}")
    print(f"  - Alertas de alta severidade: {len(high_alerts)}")
    print(f"  - Alertas de média severidade: {len(medium_alerts)}")
    
    # Resultados do teste
    results = {
        "apache_logs_collected": len(apache_logs),
        "ssh_logs_collected": len(ssh_logs),
        "apache_logs_normalized": len(normalized_apache_logs),
        "ssh_logs_normalized": len(normalized_ssh_logs),
        "brute_force_alerts": len(brute_alerts),
        "anomaly_alerts": len(anomaly_alerts),
        "total_alerts": len(alert_manager.alerts),
        "high_severity_alerts": len(high_alerts),
        "medium_severity_alerts": len(medium_alerts),
        "alerts": [alert.to_dict() for alert in alert_manager.alerts]
    }
    
    return results


def cleanup(temp_dir):
    """
    Limpa o ambiente de teste.
    
    Args:
        temp_dir: Diretório temporário a ser removido
    """
    print("Limpando ambiente de teste...")
    shutil.rmtree(temp_dir)


def main():
    """Função principal do teste de integração."""
    print("Iniciando teste de integração do Sistema de Detecção de Intrusão...")
    
    try:
        # Configurar ambiente de teste
        temp_dir, apache_log_path, ssh_log_path = setup_test_environment()
        
        # Executar teste de integração
        results = run_integration_test(apache_log_path, ssh_log_path)
        
        # Salvar resultados
        results_file = "integration_test_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, default=str, indent=2)
        
        print(f"Resultados do teste salvos em {results_file}")
        
        # Verificar resultados
        if results["brute_force_alerts"] > 0 and results["total_alerts"] > 0:
            print("\nTeste de integração PASSOU!")
            print(f"- Detectados {results['brute_force_alerts']} alertas de força bruta")
            print(f"- Detectados {results['anomaly_alerts']} alertas de anomalias")
            print(f"- Total de {results['total_alerts']} alertas gerados")
        else:
            print("\nTeste de integração FALHOU!")
            print("- Não foram detectados alertas esperados")
        
        # Limpar ambiente
        cleanup(temp_dir)
        
    except Exception as e:
        print(f"Erro durante o teste de integração: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
