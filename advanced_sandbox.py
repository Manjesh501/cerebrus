import docker
import os
import json
import time
import logging
import tempfile
import shutil
import subprocess
import threading
import hashlib
from datetime import datetime
import psutil
import requests
import socket
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('AdvancedSandbox')

class DockerSandbox:
    """
    Advanced Docker-based sandboxing environment for malware analysis
    """
    
    def __init__(self, timeout=300, memory_limit="512m", cpu_limit="1.0"):
        """
        Initialize Docker sandbox
        
        Args:
            timeout: Maximum execution time in seconds
            memory_limit: Memory limit for container
            cpu_limit: CPU limit for container
        """
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.docker_client = None
        self.container = None
        self.network_interface = None
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            raise
        
        # Create isolated network
        self.network_name = f"sandbox_network_{int(time.time())}"
        self._create_isolated_network()
        
        # Monitoring data
        self.network_traffic = []
        self.system_calls = []
        self.file_operations = []
        self.registry_operations = []
        self.memory_dumps = []
    
    def _create_isolated_network(self):
        """Create isolated Docker network for sandbox"""
        try:
            # Create custom network with no internet access
            network_config = {
                'name': self.network_name,
                'driver': 'bridge',
                'options': {
                    'com.docker.network.bridge.enable_icc': 'false',
                    'com.docker.network.bridge.enable_ip_masquerade': 'false'
                },
                'ipam': docker.types.IPAMConfig(
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet='172.20.0.0/16',
                            gateway='172.20.0.1'
                        )
                    ]
                )
            }
            
            self.network_interface = self.docker_client.networks.create(**network_config)
            logger.info(f"Created isolated network: {self.network_name}")
            
        except Exception as e:
            logger.error(f"Failed to create isolated network: {e}")
            raise
    
    def analyze_file(self, file_path, analysis_type="comprehensive"):
        """
        Analyze a file in the Docker sandbox
        
        Args:
            file_path: Path to file to analyze
            analysis_type: Type of analysis (basic, comprehensive, memory_forensics)
            
        Returns:
            dict: Analysis results
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_hash = self._calculate_hash(file_path)
        logger.info(f"Starting sandbox analysis of {os.path.basename(file_path)} (hash: {file_hash[:16]}...)")
        
        # Prepare analysis environment
        sandbox_dir = self._prepare_sandbox_environment(file_path)
        
        try:
            # Start monitoring threads
            monitor_threads = self._start_monitoring()
            
            # Run analysis in container
            analysis_results = self._run_container_analysis(sandbox_dir, file_path, analysis_type)
            
            # Stop monitoring
            self._stop_monitoring(monitor_threads)
            
            # Collect results
            results = self._collect_analysis_results(file_hash, analysis_results)
            
            return results
            
        finally:
            # Cleanup
            self._cleanup_sandbox(sandbox_dir)
    
    def _prepare_sandbox_environment(self, file_path):
        """Prepare sandbox environment with analysis tools"""
        sandbox_dir = tempfile.mkdtemp(prefix="sandbox_")
        
        # Copy target file
        target_filename = os.path.basename(file_path)
        target_path = os.path.join(sandbox_dir, target_filename)
        shutil.copy2(file_path, target_path)
        
        # Create analysis scripts
        self._create_analysis_scripts(sandbox_dir)
        
        # Create monitoring configuration
        self._create_monitoring_config(sandbox_dir)
        
        return sandbox_dir
    
    def _create_analysis_scripts(self, sandbox_dir):
        """Create analysis scripts for container"""
        
        # Windows analysis script (PowerShell)
        ps_script = '''
# Cerberus Sandbox Analysis Script
$AnalysisResults = @{}
$StartTime = Get-Date

# System Information
$AnalysisResults.SystemInfo = @{
    OS = (Get-WmiObject Win32_OperatingSystem).Caption
    Architecture = $env:PROCESSOR_ARCHITECTURE
    Memory = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    CPU = (Get-WmiObject Win32_Processor).Name
}

# Process Monitoring Function
function Monitor-Processes {
    $InitialProcesses = Get-Process | Select-Object Id, Name, Path, StartTime
    return $InitialProcesses
}

# Network Monitoring Function
function Monitor-Network {
    $NetworkConnections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
    return $NetworkConnections
}

# File System Monitoring
function Monitor-FileSystem {
    $FileChanges = @()
    # Monitor key directories
    $MonitorPaths = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "C:\\Windows\\System32")
    
    foreach ($Path in $MonitorPaths) {
        if (Test-Path $Path) {
            $Files = Get-ChildItem $Path -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime
            $FileChanges += $Files
        }
    }
    return $FileChanges
}

# Registry Monitoring
function Monitor-Registry {
    $RegistryKeys = @()
    $MonitorKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services"
    )
    
    foreach ($Key in $MonitorKeys) {
        try {
            $KeyData = Get-ItemProperty $Key -ErrorAction SilentlyContinue
            if ($KeyData) {
                $RegistryKeys += @{Key = $Key; Data = $KeyData}
            }
        } catch {}
    }
    return $RegistryKeys
}

# Initial State Capture
$InitialState = @{
    Processes = Monitor-Processes
    Network = Monitor-Network
    FileSystem = Monitor-FileSystem
    Registry = Monitor-Registry
}

# Execute Target File
$TargetFile = Get-ChildItem "C:\\analysis\\target\\*" | Select-Object -First 1
if ($TargetFile) {
    try {
        $Process = Start-Process $TargetFile.FullName -PassThru -WindowStyle Hidden
        Start-Sleep 30  # Let it run for 30 seconds
        
        if (!$Process.HasExited) {
            Stop-Process $Process -Force
        }
    } catch {
        $AnalysisResults.ExecutionError = $_.Exception.Message
    }
}

# Final State Capture
$FinalState = @{
    Processes = Monitor-Processes
    Network = Monitor-Network
    FileSystem = Monitor-FileSystem
    Registry = Monitor-Registry
}

# Analysis Results
$AnalysisResults.InitialState = $InitialState
$AnalysisResults.FinalState = $FinalState
$AnalysisResults.ExecutionTime = (Get-Date) - $StartTime
$AnalysisResults.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Save results
$AnalysisResults | ConvertTo-Json -Depth 10 | Out-File "C:\\analysis\\results\\analysis_results.json" -Encoding UTF8

Write-Host "Analysis completed successfully"
'''
        
        with open(os.path.join(sandbox_dir, "analysis.ps1"), "w", encoding="utf-8") as f:
            f.write(ps_script)
        
        # Linux analysis script (Bash)
        bash_script = '''#!/bin/bash
# Cerberus Sandbox Analysis Script for Linux

RESULTS_DIR="/analysis/results"
mkdir -p "$RESULTS_DIR"

echo "Starting sandbox analysis at $(date)"

# System Information
echo '{"system_info": {' > "$RESULTS_DIR/analysis_results.json"
echo "  \"os\": \"$(uname -a)\"," >> "$RESULTS_DIR/analysis_results.json"
echo "  \"cpu\": \"$(cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2 | xargs)\"," >> "$RESULTS_DIR/analysis_results.json"
echo "  \"memory\": \"$(free -h | grep Mem | awk '{print $2}')\"" >> "$RESULTS_DIR/analysis_results.json"
echo '},' >> "$RESULTS_DIR/analysis_results.json"

# Initial state capture
echo "\"initial_state\": {" >> "$RESULTS_DIR/analysis_results.json"
echo "  \"processes\": [" >> "$RESULTS_DIR/analysis_results.json"
ps aux --no-headers | awk '{print "    {\"pid\": "$2", \"name\": \""$11"\", \"cpu\": "$3", \"mem\": "$4"}"}' | head -20 >> "$RESULTS_DIR/analysis_results.json"
echo "  ]," >> "$RESULTS_DIR/analysis_results.json"
echo "  \"network\": [" >> "$RESULTS_DIR/analysis_results.json"
netstat -tulpn 2>/dev/null | grep LISTEN | head -10 | awk '{print "    {\"protocol\": \""$1"\", \"address\": \""$4"\"}"}' >> "$RESULTS_DIR/analysis_results.json"
echo "  ]" >> "$RESULTS_DIR/analysis_results.json"
echo "}," >> "$RESULTS_DIR/analysis_results.json"

# Execute target file
TARGET_FILE=$(find /analysis/target -type f -executable | head -1)
if [ -n "$TARGET_FILE" ]; then
    echo "Executing: $TARGET_FILE"
    timeout 30s "$TARGET_FILE" > "$RESULTS_DIR/execution_output.log" 2>&1 &
    EXEC_PID=$!
    sleep 30
    kill $EXEC_PID 2>/dev/null || true
fi

# Final state capture
echo "\"final_state\": {" >> "$RESULTS_DIR/analysis_results.json"
echo "  \"processes\": [" >> "$RESULTS_DIR/analysis_results.json"
ps aux --no-headers | awk '{print "    {\"pid\": "$2", \"name\": \""$11"\", \"cpu\": "$3", \"mem\": "$4"}"}' | head -20 >> "$RESULTS_DIR/analysis_results.json"
echo "  ]" >> "$RESULTS_DIR/analysis_results.json"
echo "}," >> "$RESULTS_DIR/analysis_results.json"
echo "\"timestamp\": \"$(date -Iseconds)\"" >> "$RESULTS_DIR/analysis_results.json"
echo "}" >> "$RESULTS_DIR/analysis_results.json"

echo "Analysis completed at $(date)"
'''
        
        with open(os.path.join(sandbox_dir, "analysis.sh"), "w") as f:
            f.write(bash_script)
        os.chmod(os.path.join(sandbox_dir, "analysis.sh"), 0o755)
    
    def _create_monitoring_config(self, sandbox_dir):
        """Create monitoring configuration files"""
        
        # Network monitoring configuration
        network_config = {
            "capture_traffic": True,
            "capture_dns": True,
            "capture_http": True,
            "max_packets": 10000,
            "timeout": self.timeout
        }
        
        with open(os.path.join(sandbox_dir, "network_config.json"), "w") as f:
            json.dump(network_config, f, indent=2)
        
        # Create results directory structure
        results_dir = os.path.join(sandbox_dir, "results")
        os.makedirs(results_dir, exist_ok=True)
        
        # Create target directory
        target_dir = os.path.join(sandbox_dir, "target")
        os.makedirs(target_dir, exist_ok=True)
    
    def _run_container_analysis(self, sandbox_dir, file_path, analysis_type):
        """Run analysis in Docker container"""
        
        # Determine container image based on file type
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in ['.exe', '.dll', '.bat', '.ps1']:
            image_name = "mcr.microsoft.com/windows/servercore:ltsc2019"
            analysis_cmd = ["powershell", "-File", "C:\\analysis\\analysis.ps1"]
        else:
            image_name = "ubuntu:20.04"
            analysis_cmd = ["/bin/bash", "/analysis/analysis.sh"]
        
        # Container configuration
        container_config = {
            'image': image_name,
            'command': analysis_cmd,
            'detach': True,
            'mem_limit': self.memory_limit,
            'cpu_period': 100000,
            'cpu_quota': int(float(self.cpu_limit) * 100000),
            'network': self.network_name,
            'volumes': {
                sandbox_dir: {
                    'bind': '/analysis' if image_name.startswith('ubuntu') else 'C:\\analysis',
                    'mode': 'rw'
                }
            },
            'environment': {
                'ANALYSIS_TYPE': analysis_type,
                'TIMEOUT': str(self.timeout)
            },
            'security_opt': ['no-new-privileges:true'],
            'cap_drop': ['ALL'],
            'cap_add': ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID'],
            'read_only': False,
            'tmpfs': {'/tmp': 'size=100M,noexec'} if image_name.startswith('ubuntu') else {}
        }
        
        try:
            # Start container
            logger.info(f"Starting analysis container with image: {image_name}")
            self.container = self.docker_client.containers.run(**container_config)
            
            # Wait for completion or timeout
            result = self.container.wait(timeout=self.timeout + 30)
            
            # Get logs
            logs = self.container.logs().decode('utf-8', errors='ignore')
            
            # Container execution results
            return {
                'exit_code': result['StatusCode'],
                'logs': logs,
                'container_id': self.container.id
            }
            
        except docker.errors.ContainerError as e:
            logger.error(f"Container execution error: {e}")
            return {'error': str(e), 'exit_code': -1}
        
        except Exception as e:
            logger.error(f"Unexpected error during container analysis: {e}")
            return {'error': str(e), 'exit_code': -2}
    
    def _start_monitoring(self):
        """Start monitoring threads for network traffic and system activity"""
        threads = []
        
        # Network traffic monitoring
        network_thread = threading.Thread(target=self._monitor_network_traffic, daemon=True)
        network_thread.start()
        threads.append(network_thread)
        
        # Resource monitoring
        resource_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        resource_thread.start()
        threads.append(resource_thread)
        
        return threads
    
    def _monitor_network_traffic(self):
        """Monitor network traffic from the container"""
        try:
            # Simple network monitoring using netstat-like approach
            start_time = time.time()
            
            while time.time() - start_time < self.timeout:
                if self.container:
                    try:
                        # Get network statistics from container
                        stats = self.container.stats(stream=False)
                        
                        if 'networks' in stats:
                            for interface, data in stats['networks'].items():
                                self.network_traffic.append({
                                    'timestamp': datetime.now().isoformat(),
                                    'interface': interface,
                                    'rx_bytes': data.get('rx_bytes', 0),
                                    'tx_bytes': data.get('tx_bytes', 0),
                                    'rx_packets': data.get('rx_packets', 0),
                                    'tx_packets': data.get('tx_packets', 0)
                                })
                    except Exception as e:
                        logger.debug(f"Network monitoring error: {e}")
                
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"Network traffic monitoring failed: {e}")
    
    def _monitor_resources(self):
        """Monitor resource usage of the container"""
        try:
            start_time = time.time()
            
            while time.time() - start_time < self.timeout:
                if self.container:
                    try:
                        stats = self.container.stats(stream=False)
                        
                        # CPU usage
                        cpu_stats = stats.get('cpu_stats', {})
                        precpu_stats = stats.get('precpu_stats', {})
                        
                        # Memory usage
                        memory_stats = stats.get('memory_stats', {})
                        
                        resource_data = {
                            'timestamp': datetime.now().isoformat(),
                            'cpu_usage': cpu_stats.get('cpu_usage', {}),
                            'memory_usage': memory_stats.get('usage', 0),
                            'memory_limit': memory_stats.get('limit', 0)
                        }
                        
                        # Store resource data
                        if not hasattr(self, 'resource_usage'):
                            self.resource_usage = []
                        self.resource_usage.append(resource_data)
                        
                    except Exception as e:
                        logger.debug(f"Resource monitoring error: {e}")
                
                time.sleep(2)
                
        except Exception as e:
            logger.error(f"Resource monitoring failed: {e}")
    
    def _stop_monitoring(self, threads):
        """Stop monitoring threads"""
        for thread in threads:
            thread.join(timeout=5)
    
    def _collect_analysis_results(self, file_hash, container_results):
        """Collect and format analysis results"""
        
        results = {
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            'sandbox_type': 'docker',
            'analysis_duration': self.timeout,
            'container_results': container_results,
            'network_traffic': self.network_traffic,
            'resource_usage': getattr(self, 'resource_usage', []),
            'security_analysis': self._perform_security_analysis()
        }
        
        return results
    
    def _perform_security_analysis(self):
        """Perform security analysis on collected data"""
        
        security_indicators = {
            'suspicious_network_activity': False,
            'high_resource_usage': False,
            'privilege_escalation_attempts': False,
            'persistence_mechanisms': False
        }
        
        # Analyze network traffic
        total_traffic = sum(t.get('tx_bytes', 0) + t.get('rx_bytes', 0) for t in self.network_traffic)
        if total_traffic > 1024 * 1024:  # More than 1MB of traffic
            security_indicators['suspicious_network_activity'] = True
        
        # Analyze resource usage
        if hasattr(self, 'resource_usage') and self.resource_usage:
            max_memory = max(r.get('memory_usage', 0) for r in self.resource_usage)
            memory_limit = self.resource_usage[0].get('memory_limit', 0) if self.resource_usage else 0
            
            if memory_limit > 0 and max_memory > memory_limit * 0.8:
                security_indicators['high_resource_usage'] = True
        
        return security_indicators
    
    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _cleanup_sandbox(self, sandbox_dir):
        """Clean up sandbox environment"""
        try:
            # Stop and remove container
            if self.container:
                try:
                    self.container.stop(timeout=10)
                    self.container.remove()
                except Exception as e:
                    logger.warning(f"Container cleanup warning: {e}")
            
            # Remove sandbox directory
            if os.path.exists(sandbox_dir):
                shutil.rmtree(sandbox_dir, ignore_errors=True)
            
            # Remove network
            if self.network_interface:
                try:
                    self.network_interface.remove()
                except Exception as e:
                    logger.warning(f"Network cleanup warning: {e}")
                    
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self._cleanup_sandbox("")

# Memory Forensics Module
class MemoryForensics:
    """Advanced memory forensics capabilities"""
    
    def __init__(self):
        self.volatility_path = self._find_volatility()
    
    def _find_volatility(self):
        """Find Volatility framework installation"""
        possible_paths = [
            "/usr/local/bin/vol.py",
            "/opt/volatility/vol.py",
            "volatility",
            "vol.py"
        ]
        
        for path in possible_paths:
            if shutil.which(path):
                return path
        
        logger.warning("Volatility framework not found. Memory forensics will be limited.")
        return None
    
    def analyze_memory_dump(self, dump_path, profile=None):
        """Analyze memory dump using Volatility"""
        if not self.volatility_path:
            return {"error": "Volatility framework not available"}
        
        if not os.path.exists(dump_path):
            return {"error": f"Memory dump not found: {dump_path}"}
        
        results = {}
        
        try:
            # Process list
            results['processes'] = self._run_volatility_command(dump_path, "pslist", profile)
            
            # Network connections
            results['network'] = self._run_volatility_command(dump_path, "netscan", profile)
            
            # DLL list
            results['dlls'] = self._run_volatility_command(dump_path, "dlllist", profile)
            
            # Registry analysis
            results['registry'] = self._run_volatility_command(dump_path, "hivelist", profile)
            
            # Malware detection
            results['malfind'] = self._run_volatility_command(dump_path, "malfind", profile)
            
        except Exception as e:
            logger.error(f"Memory forensics analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _run_volatility_command(self, dump_path, plugin, profile=None):
        """Run a Volatility command and return results"""
        try:
            cmd = [self.volatility_path, "-f", dump_path]
            
            if profile:
                cmd.extend(["--profile", profile])
            
            cmd.append(plugin)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"

# Example usage
if __name__ == "__main__":
    # Example of using the Docker sandbox
    test_file = "test_malware.exe"  # Replace with actual test file
    
    if os.path.exists(test_file):
        with DockerSandbox(timeout=120) as sandbox:
            results = sandbox.analyze_file(test_file, analysis_type="comprehensive")
            print(json.dumps(results, indent=2, default=str))
    else:
        print(f"Test file {test_file} not found")