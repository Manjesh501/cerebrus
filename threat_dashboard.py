import os
import json
import sqlite3
from datetime import datetime, timedelta
import plotly.graph_objs as go
import plotly.utils
import pandas as pd
import threading
import time

class ThreatLandscapeDashboard:
    """Real-time threat landscape dashboard with visualizations"""
    
    def __init__(self, db_path="threat_dashboard.db"):
        self.db_path = db_path
        self._init_database()
        self.threat_data = {}
        self.update_thread = None
        self.running = False
        
    def _init_database(self):
        """Initialize dashboard database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                threat_type TEXT,
                severity TEXT,
                country TEXT,
                malware_family TEXT,
                attack_vector TEXT,
                target_sector TEXT,
                source_ip TEXT,
                confidence REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE,
                malware_family TEXT,
                detection_count INTEGER,
                geographic_spread INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_vectors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                vector_type TEXT,
                frequency INTEGER,
                success_rate REAL
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Populate with sample data
        self._populate_sample_data()
    
    def _populate_sample_data(self):
        """Populate database with sample threat data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Sample threat events
        sample_events = [
            ('2024-01-20 10:30:00', 'malware', 'high', 'US', 'Emotet', 'email', 'finance', '192.168.1.100', 0.9),
            ('2024-01-20 11:15:00', 'phishing', 'medium', 'UK', 'Unknown', 'web', 'healthcare', '10.0.0.50', 0.7),
            ('2024-01-20 12:00:00', 'ransomware', 'critical', 'DE', 'Ryuk', 'email', 'manufacturing', '172.16.0.25', 0.95),
            ('2024-01-20 13:45:00', 'trojan', 'high', 'FR', 'TrickBot', 'download', 'education', '203.0.113.10', 0.85),
            ('2024-01-20 14:30:00', 'malware', 'medium', 'JP', 'Maze', 'usb', 'government', '198.51.100.5', 0.8)
        ]
        
        cursor.executemany('''
            INSERT INTO threat_events 
            (timestamp, threat_type, severity, country, malware_family, attack_vector, target_sector, source_ip, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_events)
        
        # Sample malware trends
        sample_trends = [
            ('2024-01-20', 'Emotet', 150, 25),
            ('2024-01-20', 'TrickBot', 89, 18),
            ('2024-01-20', 'Ryuk', 45, 12),
            ('2024-01-20', 'Maze', 67, 15),
            ('2024-01-21', 'Emotet', 175, 28),
            ('2024-01-21', 'TrickBot', 92, 20)
        ]
        
        cursor.executemany('''
            INSERT INTO malware_trends (date, malware_family, detection_count, geographic_spread)
            VALUES (?, ?, ?, ?)
        ''', sample_trends)
        
        # Sample attack vectors
        sample_vectors = [
            ('2024-01-20 10:00:00', 'email', 245, 0.35),
            ('2024-01-20 10:00:00', 'web', 189, 0.28),
            ('2024-01-20 10:00:00', 'download', 156, 0.42),
            ('2024-01-20 10:00:00', 'usb', 78, 0.65),
            ('2024-01-20 10:00:00', 'network', 134, 0.31)
        ]
        
        cursor.executemany('''
            INSERT INTO attack_vectors (timestamp, vector_type, frequency, success_rate)
            VALUES (?, ?, ?, ?)
        ''', sample_vectors)
        
        conn.commit()
        conn.close()
    
    def start_monitoring(self):
        """Start real-time threat monitoring"""
        self.running = True
        self.update_thread = threading.Thread(target=self._update_threat_data, daemon=True)
        self.update_thread.start()
    
    def stop_monitoring(self):
        """Stop threat monitoring"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
    
    def _update_threat_data(self):
        """Update threat data in background"""
        while self.running:
            try:
                self.threat_data = {
                    'threat_overview': self.get_threat_overview(),
                    'geographic_distribution': self.get_geographic_distribution(),
                    'malware_trends': self.get_malware_trends(),
                    'attack_vectors': self.get_attack_vector_analysis(),
                    'threat_timeline': self.get_threat_timeline(),
                    'sector_analysis': self.get_sector_analysis()
                }
                time.sleep(30)  # Update every 30 seconds
            except Exception as e:
                print(f"Error updating threat data: {e}")
                time.sleep(60)
    
    def get_threat_overview(self):
        """Get overall threat statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total threats today
        cursor.execute('''
            SELECT COUNT(*) FROM threat_events 
            WHERE DATE(timestamp) = DATE('now')
        ''')
        total_today = cursor.fetchone()[0]
        
        # Critical threats
        cursor.execute('''
            SELECT COUNT(*) FROM threat_events 
            WHERE severity = 'critical' AND DATE(timestamp) = DATE('now')
        ''')
        critical_today = cursor.fetchone()[0]
        
        # Most active malware family
        cursor.execute('''
            SELECT malware_family, COUNT(*) as count 
            FROM threat_events 
            WHERE DATE(timestamp) = DATE('now')
            GROUP BY malware_family 
            ORDER BY count DESC 
            LIMIT 1
        ''')
        top_malware = cursor.fetchone()
        
        # Average confidence
        cursor.execute('''
            SELECT AVG(confidence) FROM threat_events 
            WHERE DATE(timestamp) = DATE('now')
        ''')
        avg_confidence = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_threats': total_today,
            'critical_threats': critical_today,
            'top_malware': top_malware[0] if top_malware else 'Unknown',
            'top_malware_count': top_malware[1] if top_malware else 0,
            'average_confidence': round(avg_confidence * 100, 1)
        }
    
    def get_geographic_distribution(self):
        """Get geographic threat distribution"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT country, COUNT(*) as threat_count,
                   AVG(confidence) as avg_confidence
            FROM threat_events 
            WHERE DATE(timestamp) >= DATE('now', '-7 days')
            GROUP BY country
            ORDER BY threat_count DESC
        ''', conn)
        
        conn.close()
        
        # Create world map visualization
        data = [{
            'type': 'choropleth',
            'locations': df['country'].tolist(),
            'z': df['threat_count'].tolist(),
            'locationmode': 'ISO-3',
            'colorscale': 'Reds',
            'colorbar': {'title': 'Threat Count'}
        }]
        
        layout = {
            'title': 'Global Threat Distribution (Last 7 Days)',
            'geo': {
                'showframe': False,
                'showcoastlines': True,
                'projection': {'type': 'natural earth'}
            }
        }
        
        return {
            'data': data,
            'layout': layout,
            'country_stats': df.to_dict('records')
        }
    
    def get_malware_trends(self):
        """Get malware family trends"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT date, malware_family, SUM(detection_count) as total_detections
            FROM malware_trends 
            WHERE date >= DATE('now', '-30 days')
            GROUP BY date, malware_family
            ORDER BY date
        ''', conn)
        
        conn.close()
        
        # Create line chart
        traces = []
        for family in df['malware_family'].unique():
            family_data = df[df['malware_family'] == family]
            traces.append({
                'x': family_data['date'].tolist(),
                'y': family_data['total_detections'].tolist(),
                'name': family,
                'type': 'scatter',
                'mode': 'lines+markers'
            })
        
        layout = {
            'title': 'Malware Family Trends (Last 30 Days)',
            'xaxis': {'title': 'Date'},
            'yaxis': {'title': 'Detection Count'}
        }
        
        return {
            'data': traces,
            'layout': layout
        }
    
    def get_attack_vector_analysis(self):
        """Get attack vector analysis"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT vector_type, SUM(frequency) as total_frequency,
                   AVG(success_rate) as avg_success_rate
            FROM attack_vectors
            WHERE DATE(timestamp) >= DATE('now', '-7 days')
            GROUP BY vector_type
        ''', conn)
        
        conn.close()
        
        # Create pie chart for frequency
        frequency_chart = {
            'data': [{
                'type': 'pie',
                'labels': df['vector_type'].tolist(),
                'values': df['total_frequency'].tolist(),
                'textinfo': 'label+percent'
            }],
            'layout': {
                'title': 'Attack Vector Distribution'
            }
        }
        
        # Create bar chart for success rates
        success_rate_chart = {
            'data': [{
                'type': 'bar',
                'x': df['vector_type'].tolist(),
                'y': (df['avg_success_rate'] * 100).tolist(),
                'marker': {'color': 'red'}
            }],
            'layout': {
                'title': 'Attack Vector Success Rates',
                'xaxis': {'title': 'Attack Vector'},
                'yaxis': {'title': 'Success Rate (%)'}
            }
        }
        
        return {
            'frequency_distribution': frequency_chart,
            'success_rates': success_rate_chart,
            'summary': df.to_dict('records')
        }
    
    def get_threat_timeline(self):
        """Get threat timeline for last 24 hours"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT 
                datetime(timestamp) as hour,
                threat_type,
                severity,
                COUNT(*) as threat_count
            FROM threat_events 
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY datetime(timestamp), threat_type, severity
            ORDER BY hour
        ''', conn)
        
        conn.close()
        
        # Create timeline visualization
        traces = []
        severity_colors = {
            'low': 'green',
            'medium': 'orange', 
            'high': 'red',
            'critical': 'darkred'
        }
        
        for severity in df['severity'].unique():
            severity_data = df[df['severity'] == severity]
            traces.append({
                'x': severity_data['hour'].tolist(),
                'y': severity_data['threat_count'].tolist(),
                'name': f'{severity.title()} Severity',
                'type': 'scatter',
                'mode': 'lines+markers',
                'line': {'color': severity_colors.get(severity, 'blue')}
            })
        
        layout = {
            'title': 'Threat Timeline (Last 24 Hours)',
            'xaxis': {'title': 'Time'},
            'yaxis': {'title': 'Threat Count'}
        }
        
        return {
            'data': traces,
            'layout': layout
        }
    
    def get_sector_analysis(self):
        """Get target sector analysis"""
        conn = sqlite3.connect(self.db_path)
        
        df = pd.read_sql_query('''
            SELECT target_sector, threat_type, COUNT(*) as threat_count
            FROM threat_events 
            WHERE DATE(timestamp) >= DATE('now', '-7 days')
            GROUP BY target_sector, threat_type
        ''', conn)
        
        conn.close()
        
        # Create stacked bar chart
        sectors = df['target_sector'].unique()
        threat_types = df['threat_type'].unique()
        
        traces = []
        for threat_type in threat_types:
            threat_data = df[df['threat_type'] == threat_type]
            y_values = []
            
            for sector in sectors:
                sector_data = threat_data[threat_data['target_sector'] == sector]
                count = sector_data['threat_count'].sum() if not sector_data.empty else 0
                y_values.append(count)
            
            traces.append({
                'x': list(sectors),
                'y': y_values,
                'name': threat_type.title(),
                'type': 'bar'
            })
        
        layout = {
            'title': 'Threats by Target Sector (Last 7 Days)',
            'xaxis': {'title': 'Sector'},
            'yaxis': {'title': 'Threat Count'},
            'barmode': 'stack'
        }
        
        return {
            'data': traces,
            'layout': layout
        }
    
    def generate_threat_report(self, timeframe='24h'):
        """Generate automated threat report"""
        conn = sqlite3.connect(self.db_path)
        
        if timeframe == '24h':
            time_filter = "timestamp >= datetime('now', '-24 hours')"
        elif timeframe == '7d':
            time_filter = "timestamp >= datetime('now', '-7 days')"
        else:
            time_filter = "timestamp >= datetime('now', '-30 days')"
        
        # Get summary statistics
        cursor = conn.cursor()
        cursor.execute(f'''
            SELECT 
                COUNT(*) as total_threats,
                COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_threats,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_threats,
                AVG(confidence) as avg_confidence
            FROM threat_events 
            WHERE {time_filter}
        ''')
        
        summary = cursor.fetchone()
        
        # Get top threats
        cursor.execute(f'''
            SELECT malware_family, COUNT(*) as count
            FROM threat_events 
            WHERE {time_filter}
            GROUP BY malware_family
            ORDER BY count DESC
            LIMIT 5
        ''')
        
        top_threats = cursor.fetchall()
        
        # Get affected sectors
        cursor.execute(f'''
            SELECT target_sector, COUNT(*) as count
            FROM threat_events 
            WHERE {time_filter}
            GROUP BY target_sector
            ORDER BY count DESC
        ''')
        
        affected_sectors = cursor.fetchall()
        
        conn.close()
        
        report = {
            'timeframe': timeframe,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_threats': summary[0],
                'critical_threats': summary[1],
                'high_threats': summary[2],
                'average_confidence': round(summary[3] * 100, 1) if summary[3] else 0
            },
            'top_threats': [{'family': t[0], 'count': t[1]} for t in top_threats],
            'affected_sectors': [{'sector': s[0], 'count': s[1]} for s in affected_sectors],
            'recommendations': self._generate_recommendations(summary, top_threats)
        }
        
        return report
    
    def _generate_recommendations(self, summary, top_threats):
        """Generate security recommendations based on threat data"""
        recommendations = []
        
        if summary[1] > 0:  # Critical threats detected
            recommendations.append("Immediate action required: Critical threats detected. Review security controls.")
        
        if summary[2] > 5:  # Many high severity threats
            recommendations.append("High threat activity detected. Consider increasing monitoring and security measures.")
        
        if top_threats:
            top_family = top_threats[0][0]
            recommendations.append(f"Focus on {top_family} family threats - implement specific countermeasures.")
        
        recommendations.append("Ensure all security patches are up to date.")
        recommendations.append("Review and update incident response procedures.")
        
        return recommendations

# Flask routes for the dashboard
# Initialize dashboard instance
dashboard = ThreatLandscapeDashboard()