#!/usr/bin/env python3
"""
Script de exemplo para demonstrar o uso do Sistema de Detecção de Intrusão.
Este script gera dados de log simulados e executa o sistema para detecção de intrusões.
"""

import os
import sys
import random
import datetime
import argparse
from pathlib import Path

# Adicionar o diretório raiz ao path para importação dos módulos
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.collectors.file_collector import FileLogCollector
from src.processors.log_parser import LogNormalizer
from src.analyzers.log_analyzer import BruteForceDetector, AnomalyDetector
from src.alerting.alert_manager import Alert, AlertManager


def generate_apache_logs(output_file: str, num_logs: int = 1000, include_attacks: bool = True):
    """
    Gera logs simulados do Apache para demonstração.
    
    Args:
        output_file: Caminho para o arquivo de saída
        num_logs: Número de logs a gerar
        include_attacks: Se deve incluir padrões de ataque nos logs
    """
    print(f"Gerando {num_logs} logs Apache simulados...")
    
    # Lista de IPs para usar nos logs
    normal_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    attack_ips = [f"10.0.0.{i}" for i in range(1, 5)]
    
    # Lista de caminhos para acessos normais
    normal_paths = [
        "/", "/index.html", "/about.html", "/contact.html", "/products.html",
        "/images/logo.png", "/css/style.css", "/js/main.js"
    ]
    
    # Lista de caminhos para tentativas de ataque
    attack_paths = [
        "/admin", "/wp-login.php", "/phpmyadmin", "/?id=1'", "/cgi-bin/test.cgi",
        "/index.php?id=1%27%20OR%20%271%27=%271", "/admin.php?id=1%20or%201=1--",
        "/.env", "/config.php", "/wp-config.php.bak"
    ]
    
    # Lista de user agents
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
    ]
    
    # Gerar logs
    with open(output_file, 'w') as f:
        start_time = datetime.datetime.now() - datetime.timedelta(days=1)
        
        for i in range(num_logs):
            # Determinar se este log será um ataque (10% de chance se include_attacks for True)
            is_attack = include_attacks and random.random() < 0.1
            
            # Selecionar IP
            ip = random.choice(attack_ips if is_attack else normal_ips)
            
            # Selecionar caminho
            path = random.choice(attack_paths if is_attack else normal_paths)
            
            # Selecionar código de status (mais erros para ataques)
            if is_attack:
                status = random.choice([200, 403, 404, 500] + [403, 404] * 3)
            else:
                status = random.choice([200] * 9 + [404, 500])
            
            # Tamanho da resposta
            size = random.randint(100, 10000) if status == 200 else random.randint(50, 500)
            
            # Timestamp
            timestamp = start_time + datetime.timedelta(seconds=i*10 + random.randint(0, 5))
            timestamp_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
            
            # User agent
            user_agent = random.choice(user_agents)
            
            # Referrer
            referrer = "http://example.com" if random.random() < 0.3 else "-"
            
            # Gerar linha de log no formato Combined Log Format
            log_line = f'{ip} - - [{timestamp_str}] "GET {path} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"\n'
            f.write(log_line)
    
    print(f"Logs Apache gerados em {output_file}")


def generate_ssh_logs(output_file: str, num_logs: int = 100, include_attacks: bool = True):
    """
    Gera logs simulados de SSH para demonstração.
    
    Args:
        output_file: Caminho para o arquivo de saída
        num_logs: Número de logs a gerar
        include_attacks: Se deve incluir padrões de ataque nos logs
    """
    print(f"Gerando {num_logs} logs SSH simulados...")
    
    # Lista de IPs para usar nos logs
    normal_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    attack_ips = [f"10.0.0.{i}" for i in range(1, 5)]
    
    # Lista de usuários
    valid_users = ["admin", "user", "john", "alice", "bob"]
    invalid_users = ["root", "postgres", "mysql", "administrator", "guest"]
    
    # Gerar logs
    with open(output_file, 'w') as f:
        start_time = datetime.datetime.now() - datetime.timedelta(days=1)
        
        # Se include_attacks for True, adicionar um ataque de força bruta
        if include_attacks:
            # Selecionar um IP de ataque
            attack_ip = random.choice(attack_ips)
            
            # Gerar tentativas de força bruta (20% dos logs)
            brute_force_count = int(num_logs * 0.2)
            brute_force_start = random.randint(0, num_logs - brute_force_count)
            
            for i in range(brute_force_start, brute_force_start + brute_force_count):
                # Timestamp
                timestamp = start_time + datetime.timedelta(seconds=i*5)
                timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
                
                # Usuário (alternar entre válidos e inválidos)
                user = random.choice(valid_users + invalid_users)
                
                # Tipo de evento (principalmente falhas)
                if random.random() < 0.9:  # 90% de falhas
                    if user in invalid_users or random.random() < 0.5:
                        log_line = f'{timestamp_str} server sshd[{random.randint(1000, 9999)}]: Invalid user {user} from {attack_ip} port {random.randint(10000, 60000)}\n'
                    else:
                        log_line = f'{timestamp_str} server sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {attack_ip} port {random.randint(10000, 60000)}\n'
                else:  # 10% de sucessos
                    log_line = f'{timestamp_str} server sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {attack_ip} port {random.randint(10000, 60000)}\n'
                
                f.write(log_line)
        
        # Gerar logs normais para o restante
        remaining_logs = num_logs - (brute_force_count if include_attacks else 0)
        for i in range(remaining_logs):
            # Timestamp
            timestamp = start_time + datetime.timedelta(seconds=i*60 + random.randint(0, 30))
            timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
            
            # IP
            ip = random.choice(normal_ips)
            
            # Usuário
            user = random.choice(valid_users)
            
            # Tipo de evento (principalmente sucessos)
            if random.random() < 0.8:  # 80% de sucessos
                log_line = f'{timestamp_str} server sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {random.randint(10000, 60000)}\n'
            else:  # 20% de falhas
                log_line = f'{timestamp_str} server sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {ip} port {random.randint(10000, 60000)}\n'
            
            f.write(log_line)
    
    print(f"Logs SSH gerados em {output_file}")


def run_detection_system(apache_log_file: str, ssh_log_file: str, output_file: str):
    """
    Executa o sistema de detecção de intrusão nos logs gerados.
    
    Args:
        apache_log_file: Caminho para o arquivo de logs Apache
        ssh_log_file: Caminho para o arquivo de logs SSH
        output_file: Caminho para o arquivo de saída de alertas
    """
    print("Executando sistema de detecção de intrusão...")
    
    # Coletar logs
    apache_logs = []
    ssh_logs = []
    
    # Coletar logs Apache
    if os.path.exists(apache_log_file):
        collector = FileLogCollector(apache_log_file)
        for line in collector.collect_logs():
            apache_logs.append(line)
    
    # Coletar logs SSH
    if os.path.exists(ssh_log_file):
        collector = FileLogCollector(ssh_log_file)
        for line in collector.collect_logs():
            ssh_logs.append(line)
    
    print(f"Coletados {len(apache_logs)} logs Apache e {len(ssh_logs)} logs SSH")
    
    # Processar logs
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
    
    print(f"Normalizados {len(normalized_apache_logs)} logs Apache e {len(normalized_ssh_logs)} logs SSH")
    
    # Analisar logs
    all_alerts = []
    
    # Detector de força bruta para logs SSH
    brute_detector = BruteForceDetector(threshold=5, time_window=300)
    brute_alerts = brute_detector.analyze(normalized_ssh_logs)
    all_alerts.extend(brute_alerts)
    print(f"Detectados {len(brute_alerts)} alertas de força bruta")
    
    # Detector de anomalias para logs Apache
    if len(normalized_apache_logs) > 10:
        anomaly_detector = AnomalyDetector(contamination=0.1)
        
        # Treinar com uma parte dos logs
        train_size = min(len(normalized_apache_logs), 500)
        anomaly_detector.train(normalized_apache_logs[:train_size])
        
        # Analisar todos os logs
        anomaly_alerts = anomaly_detector.analyze(normalized_apache_logs)
        all_alerts.extend(anomaly_alerts)
        print(f"Detectados {len(anomaly_alerts)} alertas de anomalias")
    
    # Gerenciar alertas
    alert_manager = AlertManager()
    for alert_data in all_alerts:
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
    alert_manager.save_alerts(output_file)
    print(f"Salvos {len(all_alerts)} alertas em {output_file}")
    
    # Resumo
    print(f"\nResumo da Análise:")
    print(f"- Logs Apache processados: {len(normalized_apache_logs)}")
    print(f"- Logs SSH processados: {len(normalized_ssh_logs)}")
    print(f"- Alertas gerados: {len(all_alerts)}")
    
    severity_counts = {}
    for alert_data in all_alerts:
        severity = alert_data.get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        print(f"  - {severity.capitalize()}: {count}")


def main():
    """Função principal do script de exemplo."""
    parser = argparse.ArgumentParser(description='Demonstração do Sistema de Detecção de Intrusão')
    
    parser.add_argument('--output-dir', type=str, default='./data',
                        help='Diretório para salvar os arquivos gerados')
    parser.add_argument('--apache-logs', type=int, default=1000,
                        help='Número de logs Apache a gerar')
    parser.add_argument('--ssh-logs', type=int, default=100,
                        help='Número de logs SSH a gerar')
    parser.add_argument('--no-attacks', action='store_true',
                        help='Não incluir padrões de ataque nos logs')
    
    args = parser.parse_args()
    
    # Criar diretório de saída se não existir
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Caminhos para os arquivos
    apache_log_file = output_dir / "apache_access.log"
    ssh_log_file = output_dir / "ssh_auth.log"
    alerts_file = output_dir / "alerts.json"
    
    # Gerar logs simulados
    generate_apache_logs(apache_log_file, args.apache_logs, not args.no_attacks)
    generate_ssh_logs(ssh_log_file, args.ssh_logs, not args.no_attacks)
    
    # Executar sistema de detecção
    run_detection_system(apache_log_file, ssh_log_file, alerts_file)
    
    print(f"\nDemonstração concluída. Os arquivos foram salvos em {output_dir}")


if __name__ == "__main__":
    main()
