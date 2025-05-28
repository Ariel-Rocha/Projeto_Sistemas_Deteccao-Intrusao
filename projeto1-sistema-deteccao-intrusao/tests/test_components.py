#!/usr/bin/env python3
"""
Script de teste para o Sistema de Detecção de Intrusão.
Este script executa testes unitários para validar os componentes do sistema.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta

# Adicionar o diretório raiz ao path para importação dos módulos
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.collectors.file_collector import FileLogCollector
from src.processors.log_parser import LogNormalizer, ApacheLogParser, SSHLogParser
from src.analyzers.log_analyzer import BruteForceDetector
from src.alerting.alert_manager import Alert, AlertManager


class TestLogParsers(unittest.TestCase):
    """Testes para os parsers de logs."""
    
    def test_apache_log_parser(self):
        """Testa o parser de logs Apache."""
        parser = ApacheLogParser()
        
        # Log no formato Combined Log Format
        log_line = '192.168.1.100 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/start.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        result = parser.parse_line(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '192.168.1.100')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['path'], '/index.html')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['referer'], 'http://example.com/start.html')
    
    def test_ssh_log_parser(self):
        """Testa o parser de logs SSH."""
        parser = SSHLogParser()
        
        # Log de falha de autenticação SSH com usuário inválido
        log_line = 'May 15 23:45:12 server sshd[12345]: Invalid user admin from 203.0.113.100 port 22 ssh2'
        result = parser.parse_line(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['event_type'], 'invalid_user')
        self.assertEqual(result['user'], 'admin')
        self.assertEqual(result['source_ip'], '203.0.113.100')
        self.assertEqual(result['port'], 22)


class TestLogNormalizer(unittest.TestCase):
    """Testes para o normalizador de logs."""
    
    def test_normalize_apache_log(self):
        """Testa a normalização de logs Apache."""
        normalizer = LogNormalizer()
        
        log_line = '192.168.1.100 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/start.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        result = normalizer.normalize(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['log_type'], 'apache')
        self.assertEqual(result['ip'], '192.168.1.100')
        self.assertEqual(result['method'], 'GET')
    
    def test_normalize_ssh_log(self):
        """Testa a normalização de logs SSH."""
        normalizer = LogNormalizer()
        
        # Log de falha de autenticação SSH com usuário inválido
        log_line = 'May 15 23:45:12 server sshd[12345]: Invalid user admin from 203.0.113.100 port 22 ssh2'
        result = normalizer.normalize(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['log_type'], 'ssh')
        self.assertEqual(result['event_type'], 'invalid_user')
        self.assertEqual(result['source_ip'], '203.0.113.100')


class TestBruteForceDetector(unittest.TestCase):
    """Testes para o detector de força bruta."""
    
    def test_brute_force_detection(self):
        """Testa a detecção de ataques de força bruta."""
        detector = BruteForceDetector(threshold=3, time_window=60)
        
        # Criar logs simulados de tentativas de força bruta
        now = datetime.now()
        logs = []
        
        # 5 tentativas falhas do mesmo IP em um curto período
        for i in range(5):
            logs.append({
                'log_type': 'ssh',
                'event_type': 'failed_password',
                'source_ip': '192.168.1.100',
                'user': 'admin',
                'timestamp': now + timedelta(seconds=i*10),
                'raw': f'May 16 10:{i:02d}:00 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2'
            })
        
        # Adicionar alguns logs normais de outros IPs
        logs.append({
            'log_type': 'ssh',
            'event_type': 'accepted_password',
            'source_ip': '192.168.1.200',
            'user': 'john',
            'timestamp': now,
            'raw': 'May 16 10:00:00 server sshd[12346]: Accepted password for john from 192.168.1.200 port 22 ssh2'
        })
        
        alerts = detector.analyze(logs)
        
        # Deve detectar um ataque de força bruta
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['alert_type'], 'brute_force')
        self.assertEqual(alerts[0]['source_ip'], '192.168.1.100')
        self.assertEqual(alerts[0]['attempt_count'], 5)


class TestAlertManager(unittest.TestCase):
    """Testes para o gerenciador de alertas."""
    
    def test_alert_management(self):
        """Testa a adição e filtragem de alertas."""
        manager = AlertManager()
        
        # Criar alguns alertas
        alert1 = Alert(
            alert_type="brute_force",
            severity="high",
            details="Tentativa de força bruta detectada",
            source_ip="192.168.1.100"
        )
        
        alert2 = Alert(
            alert_type="anomaly",
            severity="medium",
            details="Comportamento anômalo detectado",
            source_ip="192.168.1.200"
        )
        
        # Adicionar alertas
        manager.add_alert(alert1)
        manager.add_alert(alert2)
        
        # Verificar contagem total
        self.assertEqual(len(manager.alerts), 2)
        
        # Filtrar por severidade
        high_alerts = manager.get_alerts(severity="high")
        self.assertEqual(len(high_alerts), 1)
        self.assertEqual(high_alerts[0].alert_type, "brute_force")
        
        # Atualizar status
        result = manager.update_alert_status(alert1.id, "acknowledged")
        self.assertTrue(result)
        self.assertEqual(alert1.status, "acknowledged")


if __name__ == '__main__':
    unittest.main()
