#!/usr/bin/env python3
"""
Módulo de análise de logs para detecção de anomalias.
Este módulo implementa algoritmos para analisar logs normalizados e
identificar padrões suspeitos ou anomalias que possam indicar intrusões.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta


class LogAnalyzer:
    """
    Classe base para analisadores de logs.
    
    Esta classe fornece métodos comuns para análise de logs e
    detecção de comportamentos suspeitos.
    """
    
    def __init__(self):
        """Inicializa o analisador de logs."""
        pass
    
    def analyze(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analisa uma lista de logs e identifica eventos suspeitos.
        
        Args:
            logs: Lista de logs normalizados para análise
            
        Returns:
            Lista de eventos suspeitos identificados
        """
        raise NotImplementedError("Subclasses devem implementar analyze")


class BruteForceDetector(LogAnalyzer):
    """
    Detector de tentativas de força bruta em logs de autenticação.
    """
    
    def __init__(self, threshold: int = 5, time_window: int = 300):
        """
        Inicializa o detector de força bruta.
        
        Args:
            threshold: Número de falhas de autenticação para considerar como ataque
            time_window: Janela de tempo em segundos para considerar tentativas relacionadas
        """
        super().__init__()
        self.threshold = threshold
        self.time_window = time_window
    
    def analyze(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analisa logs de autenticação para detectar tentativas de força bruta.
        
        Args:
            logs: Lista de logs normalizados de autenticação
            
        Returns:
            Lista de eventos de força bruta detectados
        """
        # Filtrar apenas logs relevantes para autenticação
        auth_logs = [
            log for log in logs 
            if log.get('log_type') == 'ssh' and 
            log.get('event_type') in ['failed_password', 'invalid_user']
        ]
        
        if not auth_logs:
            return []
        
        # Agrupar por IP de origem
        ip_attempts = {}
        for log in auth_logs:
            ip = log.get('source_ip')
            timestamp = log.get('timestamp')
            
            if not ip or not timestamp:
                continue
                
            if ip not in ip_attempts:
                ip_attempts[ip] = []
                
            ip_attempts[ip].append({
                'timestamp': timestamp,
                'user': log.get('user', 'unknown'),
                'raw': log.get('raw', '')
            })
        
        # Detectar tentativas de força bruta
        alerts = []
        for ip, attempts in ip_attempts.items():
            # Ordenar tentativas por timestamp
            attempts.sort(key=lambda x: x['timestamp'])
            
            # Verificar janelas de tempo com muitas tentativas
            for i in range(len(attempts)):
                start_time = attempts[i]['timestamp']
                end_time = start_time + timedelta(seconds=self.time_window)
                
                # Contar tentativas na janela de tempo
                window_attempts = [
                    a for a in attempts 
                    if start_time <= a['timestamp'] <= end_time
                ]
                
                if len(window_attempts) >= self.threshold:
                    # Detectou possível ataque de força bruta
                    unique_users = set(a['user'] for a in window_attempts)
                    
                    alerts.append({
                        'alert_type': 'brute_force',
                        'severity': 'high',
                        'source_ip': ip,
                        'timestamp': start_time,
                        'end_timestamp': end_time,
                        'attempt_count': len(window_attempts),
                        'unique_users': list(unique_users),
                        'details': f"Possível ataque de força bruta detectado de {ip} com {len(window_attempts)} tentativas em {self.time_window} segundos",
                        'raw_logs': [a['raw'] for a in window_attempts]
                    })
                    
                    # Avançar para depois desta janela para evitar alertas duplicados
                    while i < len(attempts) and attempts[i]['timestamp'] <= end_time:
                        i += 1
                    
                    if i >= len(attempts):
                        break
        
        return alerts


class AnomalyDetector(LogAnalyzer):
    """
    Detector de anomalias baseado em machine learning para identificar
    comportamentos incomuns em logs.
    """
    
    def __init__(self, contamination: float = 0.05):
        """
        Inicializa o detector de anomalias.
        
        Args:
            contamination: Proporção esperada de anomalias nos dados (0.0 a 0.5)
        """
        super().__init__()
        self.contamination = contamination
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.trained = False
    
    def _extract_features(self, logs: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Extrai características dos logs para análise de anomalias.
        
        Args:
            logs: Lista de logs normalizados
            
        Returns:
            DataFrame com características extraídas
        """
        # Exemplo de extração de características para logs web
        if not logs or 'log_type' not in logs[0]:
            return pd.DataFrame()
            
        if logs[0]['log_type'] == 'apache':
            # Características para logs de servidor web
            features = []
            for log in logs:
                # Extrair hora do dia
                timestamp = log.get('timestamp')
                hour = timestamp.hour if timestamp else 0
                
                # Extrair características do log
                status = log.get('status', 0)
                size = int(log.get('size', 0))
                path = log.get('path', '')
                
                # Características derivadas
                is_error = 1 if status >= 400 else 0
                is_admin_path = 1 if 'admin' in path or 'wp-login' in path else 0
                has_script = 1 if '.php' in path or '.asp' in path else 0
                has_query = 1 if '?' in path else 0
                
                features.append({
                    'hour': hour,
                    'status': status,
                    'size': size,
                    'is_error': is_error,
                    'is_admin_path': is_admin_path,
                    'has_script': has_script,
                    'has_query': has_query
                })
                
            return pd.DataFrame(features)
            
        elif logs[0]['log_type'] == 'ssh':
            # Características para logs SSH
            # Implementação simplificada para exemplo
            return pd.DataFrame()
            
        return pd.DataFrame()
    
    def train(self, logs: List[Dict[str, Any]]):
        """
        Treina o modelo de detecção de anomalias com dados históricos.
        
        Args:
            logs: Lista de logs normalizados para treinamento
        """
        features_df = self._extract_features(logs)
        if features_df.empty:
            return
            
        # Normalizar características
        X = self.scaler.fit_transform(features_df)
        
        # Treinar modelo
        self.model.fit(X)
        self.trained = True
    
    def analyze(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analisa logs para detectar anomalias usando o modelo treinado.
        
        Args:
            logs: Lista de logs normalizados para análise
            
        Returns:
            Lista de anomalias detectadas
        """
        features_df = self._extract_features(logs)
        if features_df.empty or not self.trained:
            return []
            
        # Normalizar características
        X = self.scaler.transform(features_df)
        
        # Detectar anomalias
        scores = self.model.decision_function(X)
        predictions = self.model.predict(X)
        
        # Identificar logs anômalos
        alerts = []
        for i, (score, pred) in enumerate(zip(scores, predictions)):
            if pred == -1:  # -1 indica anomalia
                log = logs[i]
                alerts.append({
                    'alert_type': 'anomaly',
                    'severity': 'medium',
                    'timestamp': log.get('timestamp', datetime.now()),
                    'anomaly_score': float(score),
                    'details': f"Comportamento anômalo detectado em log {log.get('log_type', 'unknown')}",
                    'raw_log': log.get('raw', '')
                })
        
        return alerts


if __name__ == "__main__":
    # Exemplo de uso
    import json
    from datetime import datetime, timedelta
    
    # Simular logs de tentativa de força bruta
    now = datetime.now()
    ssh_logs = []
    
    # Gerar 10 tentativas de login falhas do mesmo IP em um curto período
    for i in range(10):
        ssh_logs.append({
            'log_type': 'ssh',
            'event_type': 'failed_password',
            'source_ip': '192.168.1.100',
            'user': 'admin',
            'timestamp': now + timedelta(seconds=i*10),
            'raw': f'May 16 10:{i:02d}:00 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2'
        })
    
    # Detector de força bruta
    brute_detector = BruteForceDetector(threshold=5, time_window=120)
    alerts = brute_detector.analyze(ssh_logs)
    
    print("Alertas de força bruta detectados:")
    for alert in alerts:
        print(json.dumps(alert, default=str, indent=2))
