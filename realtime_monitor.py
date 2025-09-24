import os
import time
import hashlib
import psutil
import threading
import queue
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from malware_types import MalwareTypeDetector
import importlib.util

if importlib.util.find_spec("joblib") is not None:
    import joblib
    has_ml_model = True
    try:
        model = joblib.load('ML_model/malwareclassifier-V2.pkl')
        feature_extraction_module = __import__('feature_extraction')
        def extract_features_for_file(file_path):
            return feature_extraction_module.extract_features(file_path)
    except:
        has_ml_model = False
else:
    has_ml_model = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='realtime_monitor.log'
)
logger = logging.getLogger('RealTimeMonitor')

# Create RealtimeMonitor as an alias for compatibility
class RealtimeMonitor:
    def __init__(self, watch_directories=None, scan_interval=300):
        """Initialize the realtime monitor"""
        self.watch_directories = watch_directories or []
        self.monitor = None  # Will be created when starting
        self.is_running = False
    
    def start_monitoring(self, watch_directories=None, num_workers=2):
        """Start monitoring with optional directories"""
        if self.is_running and self.monitor:
            logger.warning("Monitoring is already running. Stop first before restarting.")
            return
            
        if watch_directories:
            self.watch_directories = watch_directories
            logger.info(f"Updated watch directories: {watch_directories}")
        
        if not self.watch_directories:
            logger.warning("No directories specified for monitoring. Using default Downloads directory.")
            default_downloads = os.path.join(os.path.expanduser('~'), 'Downloads')
            self.watch_directories = [default_downloads]
        
        # Create a new monitor instance (to avoid thread reuse issues)
        self.monitor = MalwareMonitor(self.watch_directories)
        self.monitor.start_monitoring(num_workers)
        self.is_running = True
    
    def stop_monitoring(self):
        """Stop monitoring"""
        if self.monitor:
            self.monitor.stop_monitoring()
            self.monitor = None
        self.is_running = False
    
    def get_status_report(self):
        """Get status report"""
        if self.monitor:
            return self.monitor.get_status_report()
        else:
            return {
                'suspicious_files': {},
                'suspicious_processes': {},
                'monitored_directories': self.watch_directories,
                'is_running': self.is_running
            }

class MalwareMonitor:
    def __init__(self, watch_directories=None, scan_interval=300):
        """
        Initialize the malware monitor
        
        Args:
            watch_directories: List of directories to watch for new files
            scan_interval: Interval in seconds for periodic system scans
        """
        self.watch_directories = watch_directories or []
        self.scan_interval = scan_interval
        self.file_queue = queue.Queue()
        self.malware_detector = MalwareTypeDetector()
        self.observer = None  # Will be created when starting
        self.is_running = False
        self.workers = []
        self.known_processes = set()
        self.suspicious_files = {}
        self.suspicious_processes = {}
        # Track problematic files that consistently timeout
        self.problematic_files = set()
        self.file_timeout_count = {}
        
    def start_monitoring(self, num_workers=2):
        """Start the monitoring process"""
        if self.is_running:
            logger.warning("Monitoring is already running. Stop first before restarting.")
            return
            
        if not self.watch_directories:
            logger.warning("No watch directories specified. Real-time monitoring will be limited.")
            logger.info("Please specify directories to monitor using start_monitoring(watch_directories=[...])")
        
        logger.info(f"Starting real-time malware monitoring for directories: {self.watch_directories}")
        self.is_running = True
        
        # Create a new observer (threads can only be started once)
        self.observer = Observer()
        self.workers = []  # Reset workers list
        
        # Start file event handlers only for specified directories
        for directory in self.watch_directories:
            if os.path.exists(directory):
                event_handler = FileCreatedHandler(self.file_queue)
                self.observer.schedule(event_handler, directory, recursive=True)
                logger.info(f"Watching directory: {directory}")
            else:
                logger.warning(f"Directory does not exist: {directory}")
        
        # Start the file system observer
        try:
            self.observer.start()
        except RuntimeError as e:
            logger.error(f"Failed to start observer: {e}")
            self.is_running = False
            return
        
        # Start worker threads to process files
        for i in range(num_workers):
            worker = threading.Thread(target=self._process_file_queue, daemon=True)
            worker.start()
            self.workers.append(worker)
        
        # Start periodic system scan
        scan_thread = threading.Thread(target=self._periodic_system_scan, daemon=True)
        scan_thread.start()
        self.workers.append(scan_thread)
        
        # Process monitoring is disabled due to false positives
        # process_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        # process_thread.start()
        # self.workers.append(process_thread)
        
        logger.info("Malware monitoring system started successfully")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        if not self.is_running:
            logger.info("Monitoring is not currently running")
            return
            
        logger.info("Stopping real-time malware monitoring")
        self.is_running = False
        
        # Stop the observer if it exists
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5.0)
            except Exception as e:
                logger.error(f"Error stopping observer: {e}")
            finally:
                self.observer = None
        
        # Wait for workers to finish
        for worker in self.workers:
            if worker.is_alive():
                worker.join(timeout=1.0)
        
        self.workers = []
        logger.info("Malware monitoring system stopped")
    
    def _process_file_queue(self):
        """Worker thread to process files in the queue with aggressive timeouts"""
        while self.is_running:
            try:
                file_path = self.file_queue.get(timeout=1.0)
                if not self.is_running:
                    self.file_queue.task_done()
                    break
                    
                logger.debug(f"Processing file from queue: {file_path}")
                
                # Add timeout for file analysis with more aggressive limits
                import threading
                analysis_done = threading.Event()
                analysis_error = None
                
                def analyze_with_timeout():
                    nonlocal analysis_error
                    try:
                        self._analyze_file(file_path)
                    except Exception as e:
                        analysis_error = e
                        logger.error(f"Error analyzing file {file_path}: {e}")
                    finally:
                        analysis_done.set()
                
                analysis_thread = threading.Thread(target=analyze_with_timeout, daemon=True, name=f"FileAnalysis-{os.path.basename(file_path)}")
                analysis_thread.start()
                
                # Wait for analysis to complete or timeout (reduced from 60s to 30s)
                if analysis_done.wait(timeout=30.0):
                    if analysis_error:
                        logger.error(f"Analysis failed for: {file_path} - {analysis_error}")
                    else:
                        logger.debug(f"Analysis completed for: {file_path}")
                        # Reset timeout count on successful analysis
                        if file_path in self.file_timeout_count:
                            del self.file_timeout_count[file_path]
                else:
                    logger.warning(f"Analysis timed out after 30s for: {file_path} - ABANDONING")
                    # Track timeout for this file
                    self.file_timeout_count[file_path] = self.file_timeout_count.get(file_path, 0) + 1
                    # Don't wait for the thread, just abandon it
                
                self.file_queue.task_done()
            except queue.Empty:
                pass  # Queue is empty, continue waiting
            except Exception as e:
                logger.error(f"Error processing file queue: {e}")
    
    def _analyze_file(self, file_path):
        """Analyze a file for malware with comprehensive timeout protection"""
        if not self.is_running:
            return
            
        # Check if this file has been problematic before
        if file_path in self.problematic_files:
            logger.info(f"Skipping problematic file: {file_path}")
            return
            
        # Track timeout attempts for this file
        timeout_count = self.file_timeout_count.get(file_path, 0)
        if timeout_count >= 2:  # Skip files that have timed out twice
            logger.warning(f"File has timed out {timeout_count} times, adding to blacklist: {file_path}")
            self.problematic_files.add(file_path)
            return
            
        logger.info(f"Starting analysis of file: {file_path}")
        start_time = time.time()
        
        # Check if file still exists
        if not os.path.exists(file_path):
            logger.debug(f"File no longer exists: {file_path}")
            return
        
        # Skip large files (>50MB) for performance
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:
                logger.info(f"Skipping large file ({file_size} bytes): {file_path}")
                return
        except OSError as e:
            logger.warning(f"Cannot access file: {file_path} - {e}")
            return
        
        # Comprehensive trusted paths to avoid false positives
        trusted_paths = [
            # Browsers
            'Program Files\\Google\\Chrome',
            'Program Files\\BraveSoftware\\Brave-Browser',
            'Program Files (x86)\\Microsoft\\EdgeWebView',
            'Program Files\\Mozilla Firefox',
            # Microsoft products
            'Program Files\\Microsoft Office',
            'Program Files (x86)\\Microsoft Office',
            'Program Files\\Common Files\\microsoft shared',
            # Windows system
            'WINDOWS\\System32',
            'WINDOWS\\SysWOW64',
            'WINDOWS\\SystemApps',
            'WINDOWS\\WinSxS',
            # Development tools
            'Programs\\Qoder',
            'Program Files\\Git',
            'Program Files\\Docker',
            'Program Files\\JetBrains',
            # Java runtimes (including Minecraft)
            '.minecraft\\runtime',
            'Program Files\\Java',
            'Program Files (x86)\\Java',
            # Gaming platforms
            'Program Files (x86)\\Steam',
            'Program Files\\Epic Games',
            # Other common applications
            'Program Files\\Adobe',
            'Program Files\\VideoLAN',
            'Program Files\\7-Zip',
            'Program Files\\WinRAR',
            # Node.js and development
            'Program Files\\nodejs',
            'AppData\\Roaming\\npm',
            # Python installations
            'Program Files\\Python',
            'AppData\\Local\\Programs\\Python'
        ]
        
        # Check if file is in a trusted location
        file_path_normalized = file_path.replace('/', '\\')
        for trusted_path in trusted_paths:
            if trusted_path.lower() in file_path_normalized.lower():
                logger.debug(f"Skipping trusted file: {file_path}")
                return
        
        # Only scan files in specified watch directories
        if self.watch_directories:
            in_watch_dir = False
            for watch_dir in self.watch_directories:
                watch_dir_normalized = os.path.normpath(watch_dir).lower()
                file_dir_normalized = os.path.dirname(os.path.normpath(file_path)).lower()
                if file_dir_normalized.startswith(watch_dir_normalized):
                    in_watch_dir = True
                    break
            
            if not in_watch_dir:
                logger.debug(f"Skipping file outside watch directories: {file_path}")
                return
        
        # Skip common legitimate file types that rarely contain malware
        safe_extensions = [
            '.txt', '.log', '.cfg', '.conf', '.ini', '.xml', '.json',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wav',
            '.ttf', '.otf', '.woff', '.woff2'
        ]
        
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension in safe_extensions:
            logger.debug(f"Skipping safe file type: {file_path}")
            return
            
        # Log that we're actually analyzing this file (not just debug)
        logger.info(f"Analyzing file: {file_path}")
        
        # Calculate file hash with timeout
        file_hash = None
        try:
            logger.debug(f"Calculating hash for: {file_path}")
            hash_start = time.time()
            file_hash = self.malware_detector.calculate_file_hash(file_path)
            hash_time = time.time() - hash_start
            logger.debug(f"Hash calculation took {hash_time:.2f}s for: {file_path}")
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return
        
        # First, check with malware type detector with better timeout handling
        try:
            logger.debug(f"Starting malware type detection for: {file_path}")
            detection_start = time.time()
            
            # Use a more aggressive timeout for malware detection
            import signal
            import threading
            detection_result = {'result': None, 'error': None, 'completed': False}
            
            def malware_detection():
                try:
                    detection_result['result'] = self.malware_detector.detect_malware_type(file_path)
                    detection_result['completed'] = True
                    logger.debug(f"Malware detection completed for: {file_path}")
                except Exception as e:
                    detection_result['error'] = str(e)
                    detection_result['completed'] = True
                    logger.error(f"Error in malware detection for {file_path}: {e}")
            
            detection_thread = threading.Thread(target=malware_detection, daemon=True, name=f"MalwareDetection-{os.path.basename(file_path)}")
            detection_thread.start()
            detection_thread.join(timeout=15.0)  # Reduced to 15 seconds
            
            detection_time = time.time() - detection_start
            
            if detection_thread.is_alive():
                logger.warning(f"Malware detection timed out after {detection_time:.1f}s for: {file_path}")
                # Force kill the analysis for this file
                return
            elif not detection_result['completed']:
                logger.warning(f"Malware detection did not complete for: {file_path}")
                return
            elif detection_result['error']:
                logger.error(f"Error detecting malware type for {file_path}: {detection_result['error']}")
            elif detection_result['result']:
                result = detection_result['result']
                logger.debug(f"Malware detection took {detection_time:.2f}s for: {file_path}")
                # Increase confidence threshold to reduce false positives
                if result["confidence"] > 0.7:  # Increased from 0.5 to 0.7
                    logger.warning(f"Potential {result['detected_type']} detected: {file_path}")
                    self.suspicious_files[file_path] = result
        except Exception as e:
            logger.error(f"Error detecting malware type: {e}")
        
        # ML model analysis with aggressive timeout
        if has_ml_model:
            try:
                file_extension = os.path.splitext(file_path)[1].lower()
                if file_extension in ['.exe', '.dll']:
                    logger.debug(f"Starting ML analysis for: {file_path}")
                    ml_start = time.time()
                    
                    # Add timeout and safety checks for ML analysis
                    import signal
                    import threading
                    
                    result = {'prediction': None, 'error': None, 'completed': False}
                    
                    def ml_analysis():
                        try:
                            logger.debug(f"Extracting features for: {file_path}")
                            features = extract_features_for_file(file_path)
                            if features is not None:
                                logger.debug(f"Running ML prediction for: {file_path}")
                                prediction = model.predict(features)
                                result['prediction'] = prediction
                            result['completed'] = True
                            logger.debug(f"ML analysis completed for: {file_path}")
                        except Exception as e:
                            result['error'] = str(e)
                            result['completed'] = True
                            logger.error(f"Error in ML analysis for {file_path}: {e}")
                    
                    # Run ML analysis with aggressive timeout
                    ml_thread = threading.Thread(target=ml_analysis, daemon=True, name=f"MLAnalysis-{os.path.basename(file_path)}")
                    ml_thread.start()
                    ml_thread.join(timeout=20.0)  # Reduced to 20 seconds
                    
                    ml_time = time.time() - ml_start
                    
                    if ml_thread.is_alive():
                        logger.warning(f"ML analysis timed out after {ml_time:.1f}s for: {file_path}")
                        # Force abandon this analysis
                        return
                    elif not result['completed']:
                        logger.warning(f"ML analysis did not complete for: {file_path}")
                        return
                    elif result['error']:
                        logger.error(f"Error in ML analysis for {file_path}: {result['error']}")
                    elif result['prediction'] is not None and result['prediction'][0] == 1:
                        logger.warning(f"ML model detected malware: {file_path}")
                        if file_path in self.suspicious_files:
                            self.suspicious_files[file_path]["ml_detection"] = True
                        else:
                            self.suspicious_files[file_path] = {
                                "detected_type": "Unknown (ML Detection)",
                                "confidence": 0.8,
                                "file_hash": file_hash,
                                "ml_detection": True
                            }
                    else:
                        logger.debug(f"ML analysis took {ml_time:.2f}s for: {file_path}")
            except Exception as e:
                logger.error(f"Error running ML analysis: {e}")
        
        # Log completion
        total_time = time.time() - start_time
        logger.info(f"Analysis completed for {file_path} in {total_time:.2f}s")

    def _periodic_system_scan(self):
        """Periodically scan ONLY the specified watch directories"""
        scan_count = 0
        while self.is_running:
            scan_count += 1
            logger.info(f"Starting periodic system scan #{scan_count}")
            
            # ONLY scan user-specified directories, not random system directories
            if not self.watch_directories:
                logger.info("No watch directories specified, skipping periodic scan")
                time.sleep(self.scan_interval)
                continue
            
            files_queued = 0
            max_files_per_scan = 100  # Limit to prevent overwhelming the system
            
            for directory in self.watch_directories:
                if not self.is_running:  # Check if we should stop
                    break
                    
                if os.path.exists(directory):
                    logger.info(f"Scanning directory: {directory}")
                    try:
                        all_files = []
                        dangerous_files = []
                        skipped_files = []
                        
                        for root, _, files in os.walk(directory):
                            if not self.is_running or files_queued >= max_files_per_scan:
                                break
                                
                            for file in files:
                                if not self.is_running or files_queued >= max_files_per_scan:
                                    break
                                    
                                file_path = os.path.join(root, file)
                                all_files.append(file)
                                
                                # Skip already processed files that are in blacklist
                                if file_path in self.problematic_files:
                                    logger.debug(f"Skipping blacklisted file: {file_path}")
                                    skipped_files.append(f"{file} (blacklisted)")
                                    continue
                                    
                                # Only scan potentially dangerous files (expanded list)
                                dangerous_extensions = ('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.class', 
                                                       '.docm', '.xlsm', '.pptm', '.zip', '.rar', '.7z', '.msi', '.deb', '.rpm', 
                                                       '.dmg', '.pkg', '.app', '.com', '.pif', '.hta', '.wsf', '.wsh')
                                
                                if file.endswith(dangerous_extensions):
                                    dangerous_files.append(file)
                                    if self.file_queue.qsize() < 50:  # Don't overwhelm the queue
                                        # Check if file is already being processed or was recently processed
                                        if file_path not in self.suspicious_files:
                                            self.file_queue.put(file_path)
                                            files_queued += 1
                                            logger.debug(f"Queued file for analysis: {file_path}")
                                        else:
                                            logger.debug(f"File already analyzed: {file_path}")
                                            skipped_files.append(f"{file} (already analyzed)")
                                    else:
                                        logger.debug("File queue is full, skipping additional files")
                                        break
                                else:
                                    skipped_files.append(f"{file} (safe extension: {os.path.splitext(file)[1]})")
                                    logger.debug(f"Skipping non-dangerous file: {file_path} (extension: {os.path.splitext(file)[1]})")
                        
                        # Log summary of scan results
                        logger.info(f"Directory scan summary for {directory}:")
                        logger.info(f"  Total files found: {len(all_files)}")
                        logger.info(f"  Dangerous files: {len(dangerous_files)} - {dangerous_files}")
                        logger.info(f"  Skipped files: {len(skipped_files)} - {[f.split(' (')[0] for f in skipped_files[:5]]}{'...' if len(skipped_files) > 5 else ''}")
                        
                    except Exception as e:
                        logger.error(f"Error scanning directory {directory}: {e}")
                else:
                    logger.warning(f"Watch directory does not exist: {directory}")
            
            logger.info(f"Periodic scan #{scan_count} completed, queued {files_queued} files for analysis")
            logger.info(f"Current queue size: {self.file_queue.qsize()}, Suspicious files: {len(self.suspicious_files)}, Blacklisted: {len(self.problematic_files)}")
            
            # Sleep until next scan
            sleep_time = 0
            while sleep_time < self.scan_interval and self.is_running:
                time.sleep(1)
                sleep_time += 1
                
                # Log status every 30 seconds during sleep
                if sleep_time % 30 == 0 and sleep_time < self.scan_interval:
                    logger.info(f"Monitor status - Queue: {self.file_queue.qsize()}, Suspicious: {len(self.suspicious_files)}, Blacklisted: {len(self.problematic_files)}")
    
    def _monitor_processes(self):
        """Monitor running processes for suspicious activity - DISABLED due to false positives"""
        # DISABLED: This was causing too many false positives with legitimate software
        # The process monitoring needs better heuristics before it can be useful
        logger.info("Process monitoring disabled - too many false positives")
        
        # Simple loop to keep thread alive but do nothing
        while self.is_running:
            time.sleep(30)
        
        return
    
    def get_status_report(self):
        """Generate a status report of detected threats"""
        return {
            'suspicious_files': self.suspicious_files,
            'suspicious_processes': self.suspicious_processes,
            'monitored_directories': self.watch_directories,
            'is_running': self.is_running,
            'problematic_files': list(self.problematic_files),
            'file_timeout_counts': dict(self.file_timeout_count),
            'queue_size': self.file_queue.qsize()
        }
    
    def add_to_blacklist(self, file_path):
        """Manually add a file to the problematic files blacklist"""
        self.problematic_files.add(file_path)
        logger.info(f"Added file to blacklist: {file_path}")
    
    def remove_from_blacklist(self, file_path):
        """Remove a file from the problematic files blacklist"""
        self.problematic_files.discard(file_path)
        self.file_timeout_count.pop(file_path, None)
        logger.info(f"Removed file from blacklist: {file_path}")


class FileCreatedHandler(FileSystemEventHandler):
    """Watches for file creation events and adds them to the queue"""
    def __init__(self, file_queue):
        self.file_queue = file_queue
    
    def on_created(self, event):
        if not event.is_directory:
            # Only queue potentially dangerous files
            file_path = event.src_path
            if self._is_potentially_dangerous(file_path):
                # Avoid overwhelming the queue
                if self.file_queue.qsize() < 20:  # Limit queue size
                    self.file_queue.put(file_path)
                else:
                    logger.debug(f"File queue is full, skipping file: {file_path}")
    
    def on_modified(self, event):
        if not event.is_directory:
            # Only queue potentially dangerous files
            file_path = event.src_path
            if self._is_potentially_dangerous(file_path):
                # Avoid overwhelming the queue
                if self.file_queue.qsize() < 20:  # Limit queue size
                    self.file_queue.put(file_path)
                else:
                    logger.debug(f"File queue is full, skipping file: {file_path}")
    
    def _is_potentially_dangerous(self, file_path):
        """Check if file type is potentially dangerous and worth scanning"""
        dangerous_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', 
            '.jar', '.class', '.msi', '.app', '.dmg', '.deb', '.rpm',
            '.docm', '.xlsm', '.pptm', '.zip', '.rar', '.7z', '.tar', '.gz',
            '.com', '.pif', '.hta', '.wsf', '.wsh', '.jse', '.vbe'
        }
        
        file_extension = os.path.splitext(file_path)[1].lower()
        return file_extension in dangerous_extensions


if __name__ == "__main__":
    watch_dirs = [
        os.path.join(os.path.expanduser('~'), 'Downloads'), 
        os.path.join(os.path.expanduser('~'), 'Documents')
    ]
    
    monitor = MalwareMonitor(watch_directories=watch_dirs)
    monitor.start_monitoring()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(10)
            status = monitor.get_status_report()
            print(f"Monitoring {len(status['monitored_directories'])} directories")
            print(f"Suspicious files detected: {len(status['suspicious_files'])}")
            print(f"Suspicious processes detected: {len(status['suspicious_processes'])}")
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("Monitoring stopped") 