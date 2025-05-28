#!/usr/bin/env python3
"""
Sistema de alertas para notificação de eventos de segurança.
Este módulo implementa funcionalidades para geração, gerenciamento e envio de alertas
baseados em eventos de segurança detectados.
"""

import json
import logging
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional, Union, Callable


class Alert:
    """
    Classe que representa um alerta de segurança.
    """
    
    def __init__(self, alert_type: str, severity: str, details: str, 
                 timestamp: Optional[datetime.datetime] = None,
                 source_ip: Optional[str] = None,
                 raw_logs: Optional[List[str]] = None):
        """
        Inicializa um alerta de segurança.
        
        Args:
            alert_type: Tipo do alerta (ex: 'brute_force', 'anomaly', 'intrusion')
            severity: Severidade do alerta ('low', 'medium', 'high', 'critical')
            details: Descrição detalhada do alerta
            timestamp: Momento em que o alerta foi gerado
            source_ip: Endereço IP de origem relacionado ao alerta
            raw_logs: Logs brutos relacionados ao alerta
        """
        self.alert_type = alert_type
        self.severity = severity
        self.details = details
        self.timestamp = timestamp or datetime.datetime.now()
        self.source_ip = source_ip
        self.raw_logs = raw_logs or []
        self.id = f"{self.timestamp.strftime('%Y%m%d%H%M%S')}-{hash(self.details) % 10000:04d}"
        self.status = "new"  # new, acknowledged, resolved, false_positive
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte o alerta para um dicionário.
        
        Returns:
            Dicionário representando o alerta
        """
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'details': self.details,
            'timestamp': self.timestamp,
            'source_ip': self.source_ip,
            'raw_logs': self.raw_logs,
            'status': self.status
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """
        Cria um alerta a partir de um dicionário.
        
        Args:
            data: Dicionário contendo dados do alerta
            
        Returns:
            Objeto Alert criado a partir do dicionário
        """
        alert = cls(
            alert_type=data.get('alert_type', 'unknown'),
            severity=data.get('severity', 'medium'),
            details=data.get('details', ''),
            timestamp=data.get('timestamp'),
            source_ip=data.get('source_ip'),
            raw_logs=data.get('raw_logs', [])
        )
        alert.id = data.get('id', alert.id)
        alert.status = data.get('status', 'new')
        return alert
    
    def __str__(self) -> str:
        """Representação em string do alerta."""
        return f"[{self.severity.upper()}] {self.alert_type}: {self.details}"


class AlertManager:
    """
    Gerenciador de alertas para processamento e notificação.
    """
    
    def __init__(self):
        """Inicializa o gerenciador de alertas."""
        self.alerts = []
        self.notifiers = []
        self.logger = logging.getLogger("AlertManager")
    
    def add_alert(self, alert: Alert) -> None:
        """
        Adiciona um alerta ao gerenciador.
        
        Args:
            alert: Alerta a ser adicionado
        """
        self.alerts.append(alert)
        self.logger.info(f"Novo alerta adicionado: {alert}")
        
        # Notificar todos os notificadores registrados
        for notifier in self.notifiers:
            try:
                notifier(alert)
            except Exception as e:
                self.logger.error(f"Erro ao notificar: {e}")
    
    def add_notifier(self, notifier: Callable[[Alert], None]) -> None:
        """
        Registra uma função de notificação.
        
        Args:
            notifier: Função que recebe um alerta e envia notificação
        """
        self.notifiers.append(notifier)
    
    def get_alerts(self, severity: Optional[str] = None, 
                  status: Optional[str] = None,
                  limit: Optional[int] = None) -> List[Alert]:
        """
        Obtém alertas filtrados por severidade e/ou status.
        
        Args:
            severity: Filtrar por severidade
            status: Filtrar por status
            limit: Limitar número de alertas retornados
            
        Returns:
            Lista de alertas filtrados
        """
        filtered = self.alerts
        
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
            
        if status:
            filtered = [a for a in filtered if a.status == status]
            
        # Ordenar por timestamp (mais recentes primeiro)
        filtered.sort(key=lambda a: a.timestamp, reverse=True)
        
        if limit:
            filtered = filtered[:limit]
            
        return filtered
    
    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        """
        Atualiza o status de um alerta.
        
        Args:
            alert_id: ID do alerta a ser atualizado
            new_status: Novo status ('acknowledged', 'resolved', 'false_positive')
            
        Returns:
            True se o alerta foi atualizado, False caso contrário
        """
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.status = new_status
                self.logger.info(f"Alerta {alert_id} atualizado para {new_status}")
                return True
                
        return False
    
    def save_alerts(self, filename: str) -> None:
        """
        Salva todos os alertas em um arquivo JSON.
        
        Args:
            filename: Nome do arquivo para salvar
        """
        with open(filename, 'w') as f:
            json.dump([a.to_dict() for a in self.alerts], f, default=str, indent=2)
    
    def load_alerts(self, filename: str) -> None:
        """
        Carrega alertas de um arquivo JSON.
        
        Args:
            filename: Nome do arquivo para carregar
        """
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.alerts = [Alert.from_dict(item) for item in data]
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Erro ao carregar alertas: {e}")


class EmailNotifier:
    """
    Notificador de alertas por e-mail.
    """
    
    def __init__(self, smtp_server: str, smtp_port: int, 
                 username: str, password: str,
                 from_email: str, to_emails: List[str],
                 min_severity: str = 'medium'):
        """
        Inicializa o notificador de e-mail.
        
        Args:
            smtp_server: Servidor SMTP
            smtp_port: Porta do servidor SMTP
            username: Nome de usuário para autenticação SMTP
            password: Senha para autenticação SMTP
            from_email: Endereço de e-mail de origem
            to_emails: Lista de endereços de e-mail de destino
            min_severity: Severidade mínima para enviar notificações
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails
        self.min_severity = min_severity
        self.severity_levels = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }
        self.logger = logging.getLogger("EmailNotifier")
    
    def __call__(self, alert: Alert) -> None:
        """
        Envia notificação por e-mail para um alerta.
        
        Args:
            alert: Alerta a ser notificado
        """
        # Verificar se a severidade é suficiente para notificar
        if self.severity_levels.get(alert.severity, 0) < self.severity_levels.get(self.min_severity, 0):
            return
            
        # Criar mensagem
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = ', '.join(self.to_emails)
        msg['Subject'] = f"[ALERTA {alert.severity.upper()}] {alert.alert_type}"
        
        # Corpo da mensagem
        body = f"""
        <html>
        <body>
            <h2>Alerta de Segurança</h2>
            <p><strong>ID:</strong> {alert.id}</p>
            <p><strong>Tipo:</strong> {alert.alert_type}</p>
            <p><strong>Severidade:</strong> {alert.severity}</p>
            <p><strong>Timestamp:</strong> {alert.timestamp}</p>
            <p><strong>Detalhes:</strong> {alert.details}</p>
            
            {f'<p><strong>IP de Origem:</strong> {alert.source_ip}</p>' if alert.source_ip else ''}
            
            {f'<h3>Logs Relacionados:</h3><pre>{"<br>".join(alert.raw_logs)}</pre>' if alert.raw_logs else ''}
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Enviar e-mail
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            self.logger.info(f"E-mail de alerta enviado: {alert.id}")
        except Exception as e:
            self.logger.error(f"Erro ao enviar e-mail: {e}")


if __name__ == "__main__":
    # Configurar logging
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Exemplo de uso
    manager = AlertManager()
    
    # Criar alguns alertas de exemplo
    alerts = [
        Alert(
            alert_type="brute_force",
            severity="high",
            details="Tentativa de força bruta detectada no SSH",
            source_ip="192.168.1.100",
            raw_logs=["May 16 10:00:00 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2"]
        ),
        Alert(
            alert_type="anomaly",
            severity="medium",
            details="Comportamento anômalo detectado em logs de acesso web",
            source_ip="192.168.1.200"
        )
    ]
    
    # Adicionar alertas ao gerenciador
    for alert in alerts:
        manager.add_alert(alert)
    
    # Salvar alertas em arquivo
    manager.save_alerts("example_alerts.json")
    
    # Obter alertas de alta severidade
    high_alerts = manager.get_alerts(severity="high")
    print(f"Alertas de alta severidade: {len(high_alerts)}")
    for alert in high_alerts:
        print(f"  - {alert}")
