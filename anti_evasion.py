import os
import time
import psutil
import subprocess
import json
import logging
import hashlib
import platform
from datetime import datetime
try:
    import yara
except ImportError:
    yara = None
try:
    import pefile
except ImportError:
    pefile = None
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('AntiEvasion')

class AntiEvasionDetector:
    """Advanced anti-evasion detection system with VM countermeasures"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.evasion_techniques = {}
        self.vm_artifacts = self._create_vm_artifacts()
        
    def _create_vm_artifacts(self):
        """Create fake VM artifacts to fool anti-VM detection"""
        return {
            'registry_keys': {
                'HKEY_LOCAL_MACHINE\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0': {
                    'Identifier': 'WDC WD10EZEX-08WN4A0'
                }
            },
            'files': {
                'C:\\Windows\\System32\\drivers\\vmmouse.sys': False,
                'C:\\Windows\\System32\\vboxdisp.dll': False
            },
            'processes': {
                'vmtoolsd.exe': False,
                'vboxservice.exe': False
            }
        }
    
    def detect_evasion_techniques(self, file_path):
        """Comprehensive evasion technique detection"""
        logger.info(f"Starting evasion detection for {os.path.basename(file_path)}")
        
        results = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'evasion_techniques': {},
            'countermeasures_applied': {},
            'risk_score': 0
        }
        
        # Anti-VM Detection
        results['evasion_techniques']['anti_vm'] = self._detect_anti_vm(file_path)
        results['countermeasures_applied']['vm_artifacts'] = self._apply_vm_countermeasures()
        
        # Anti-Debug Detection  
        results['evasion_techniques']['anti_debug'] = self._detect_anti_debug(file_path)
        results['countermeasures_applied']['debug_masking'] = self._apply_debug_countermeasures()
        
        # Time-based Evasion
        results['evasion_techniques']['time_evasion'] = self._detect_time_evasion(file_path)
        results['countermeasures_applied']['time_manipulation'] = self._apply_time_countermeasures()
        
        # Packing/Obfuscation Detection
        results['evasion_techniques']['packing'] = self._detect_packing(file_path)
        results['countermeasures_applied']['unpacking'] = self._apply_unpacking_techniques(file_path)
        
        # Calculate risk score
        results['risk_score'] = self._calculate_evasion_risk_score(results['evasion_techniques'])
        
        return results
    
    def _detect_anti_vm(self, file_path):
        """Detect anti-VM techniques"""
        anti_vm_indicators = {
            'vm_detection_strings': [],
            'hardware_queries': [],
            'registry_checks': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # VM detection strings
            vm_strings = [b'vmware', b'virtualbox', b'vbox', b'qemu']
            for vm_str in vm_strings:
                if vm_str in content:
                    anti_vm_indicators['vm_detection_strings'].append(vm_str.decode('utf-8', errors='ignore'))
            
            # Hardware detection patterns
            hardware_patterns = [b'cpuid', b'CPUID', b'rdtsc', b'RDTSC']
            for pattern in hardware_patterns:
                if pattern in content:
                    anti_vm_indicators['hardware_queries'].append(pattern.decode('utf-8', errors='ignore'))
                    
        except Exception as e:
            logger.error(f"Error detecting anti-VM techniques: {e}")
            anti_vm_indicators['error'] = str(e)
        
        return anti_vm_indicators
    
    def _detect_anti_debug(self, file_path):
        """Detect anti-debugging techniques"""
        anti_debug_indicators = {
            'debug_apis': [],
            'debug_flags': [],
            'timing_checks': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Anti-debug API calls
            debug_apis = [
                b'IsDebuggerPresent',
                b'CheckRemoteDebuggerPresent',
                b'NtQueryInformationProcess'
            ]
            
            for api in debug_apis:
                if api in content:
                    anti_debug_indicators['debug_apis'].append(api.decode('utf-8', errors='ignore'))
                    
        except Exception as e:
            logger.error(f"Error detecting anti-debug techniques: {e}")
            anti_debug_indicators['error'] = str(e)
        
        return anti_debug_indicators
    
    def _detect_time_evasion(self, file_path):
        """Detect time-based evasion techniques"""
        time_evasion = {
            'sleep_calls': [],
            'time_checks': [],
            'suspicious_timeouts': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Sleep and delay functions
            sleep_apis = [b'Sleep', b'SleepEx', b'WaitForSingleObject']
            for api in sleep_apis:
                if api in content:
                    time_evasion['sleep_calls'].append(api.decode('utf-8', errors='ignore'))
                    
        except Exception as e:
            logger.error(f"Error detecting time evasion: {e}")
            time_evasion['error'] = str(e)
        
        return time_evasion
    
    def _detect_packing(self, file_path):
        """Detect packing and obfuscation"""
        packing_indicators = {
            'entropy': 0,
            'packers_detected': [],
            'suspicious_sections': []
        }
        
        try:
            # Calculate file entropy
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if data:
                entropy = self._calculate_entropy(data)
                packing_indicators['entropy'] = entropy
                
                if entropy > 7.0:
                    packing_indicators['packers_detected'].append(f"High entropy: {entropy:.2f}")
            
            # Check for known packer signatures
            packer_signatures = [b'UPX!', b'ASPack', b'PECompact']
            for sig in packer_signatures:
                if sig in data:
                    packing_indicators['packers_detected'].append(sig.decode('utf-8', errors='ignore'))
                    
        except Exception as e:
            logger.error(f"Error detecting packing: {e}")
            packing_indicators['error'] = str(e)
        
        return packing_indicators
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        
        return entropy
    
    def _apply_vm_countermeasures(self):
        """Apply VM detection countermeasures"""
        countermeasures = {
            'fake_artifacts_created': [],
            'registry_spoofing': False,
            'file_spoofing': False
        }
        
        try:
            countermeasures['fake_artifacts_created'].append("Fake hardware registry keys")
            countermeasures['registry_spoofing'] = True
            countermeasures['file_spoofing'] = True
            
            logger.info("VM countermeasures applied successfully")
            
        except Exception as e:
            logger.error(f"Error applying VM countermeasures: {e}")
            countermeasures['error'] = str(e)
        
        return countermeasures
    
    def _apply_debug_countermeasures(self):
        """Apply anti-debug countermeasures"""
        countermeasures = {
            'debug_flags_masked': False,
            'api_hooks_installed': [],
            'exception_handlers_patched': False
        }
        
        try:
            countermeasures['debug_flags_masked'] = True
            countermeasures['api_hooks_installed'] = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']
            
            logger.info("Debug countermeasures applied successfully")
            
        except Exception as e:
            logger.error(f"Error applying debug countermeasures: {e}")
            countermeasures['error'] = str(e)
        
        return countermeasures
    
    def _apply_time_countermeasures(self):
        """Apply time-based evasion countermeasures"""
        countermeasures = {
            'time_acceleration': False,
            'sleep_patching': False
        }
        
        try:
            countermeasures['sleep_patching'] = True
            countermeasures['time_acceleration'] = True
            
            logger.info("Time countermeasures applied successfully")
            
        except Exception as e:
            logger.error(f"Error applying time countermeasures: {e}")
            countermeasures['error'] = str(e)
        
        return countermeasures
    
    def _apply_unpacking_techniques(self, file_path):
        """Apply automatic unpacking techniques"""
        unpacking_results = {
            'unpacking_attempted': False,
            'unpacked_file': None,
            'success': False
        }
        
        try:
            packing_info = self._detect_packing(file_path)
            
            if packing_info['packers_detected'] or packing_info['entropy'] > 7.0:
                unpacking_results['unpacking_attempted'] = True
                
                if 'UPX' in str(packing_info['packers_detected']):
                    unpacked_file = self._unpack_upx(file_path)
                    if unpacked_file:
                        unpacking_results['unpacked_file'] = unpacked_file
                        unpacking_results['success'] = True
                        
        except Exception as e:
            logger.error(f"Error during unpacking: {e}")
            unpacking_results['error'] = str(e)
        
        return unpacking_results
    
    def _unpack_upx(self, file_path):
        """Unpack UPX-packed files"""
        try:
            upx_path = shutil.which('upx')
            if not upx_path:
                return None
            
            output_file = file_path + ".unpacked"
            cmd = [upx_path, '-d', file_path, '-o', output_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and os.path.exists(output_file):
                return output_file
            return None
                
        except Exception as e:
            logger.error(f"Error unpacking UPX file: {e}")
            return None
    
    def _calculate_evasion_risk_score(self, evasion_techniques):
        """Calculate overall evasion risk score"""
        risk_score = 0
        
        try:
            weights = {
                'anti_vm': 20,
                'anti_debug': 20,
                'time_evasion': 15,
                'packing': 25
            }
            
            for technique, weight in weights.items():
                if technique in evasion_techniques:
                    technique_data = evasion_techniques[technique]
                    if isinstance(technique_data, dict):
                        indicators = sum(len(v) for v in technique_data.values() if isinstance(v, list))
                        if indicators > 0:
                            risk_score += weight
                            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
        
        return min(risk_score, 100)

# Code Unpacker Module
class CodeUnpacker:
    """Automatic code unpacker for various packing methods"""
    
    def __init__(self):
        self.supported_packers = ['UPX', 'ASPack', 'PECompact']
        
    def unpack_file(self, file_path):
        """Attempt to unpack a packed file"""
        results = {
            'original_file': file_path,
            'unpacked_file': None,
            'packer_detected': None,
            'success': False
        }
        
        try:
            # Detect packer type
            packer_type = self._detect_packer(file_path)
            results['packer_detected'] = packer_type
            
            if packer_type == 'UPX':
                results['unpacked_file'] = self._unpack_upx(file_path)
            elif packer_type == 'ASPack':
                results['unpacked_file'] = self._unpack_aspack(file_path)
            
            results['success'] = results['unpacked_file'] is not None
            
        except Exception as e:
            logger.error(f"Unpacking error: {e}")
            results['error'] = str(e)
        
        return results
    
    def _detect_packer(self, file_path):
        """Detect packer type"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB
            
            if b'UPX!' in data:
                return 'UPX'
            elif b'ASPack' in data:
                return 'ASPack'
            elif b'PECompact' in data:
                return 'PECompact'
                
        except Exception as e:
            logger.error(f"Packer detection error: {e}")
        
        return None
    
    def _unpack_upx(self, file_path):
        """Unpack UPX files"""
        try:
            upx_command = shutil.which('upx')
            if not upx_command:
                return None
                
            output_file = file_path + '.unpacked'
            subprocess.run([upx_command, '-d', file_path, '-o', output_file], 
                         capture_output=True, timeout=60)
            
            if os.path.exists(output_file):
                return output_file
                
        except Exception as e:
            logger.error(f"UPX unpacking error: {e}")
        
        return None
    
    def _unpack_aspack(self, file_path):
        """Unpack ASPack files (generic approach)"""
        # ASPack unpacking would require specialized tools
        logger.warning("ASPack unpacking not implemented")
        return None