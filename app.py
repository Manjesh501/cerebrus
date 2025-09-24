from flask import Flask, request, render_template, jsonify, send_file, redirect, url_for, flash
import joblib
import os
import logging
import importlib.util
import json
import hashlib
import tempfile
import shutil
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, jsonify, redirect, url_for, make_response
from werkzeug.utils import secure_filename
import os
import json
import hashlib
import logging
from datetime import datetime
import threading
import argparse
try:
    import magic
except ImportError:
    # Fallback for Windows if magic library is not available
    magic = None
    import mimetypes
import numpy as np
import re

# Import new advanced modules
try:
    from advanced_sandbox import DockerSandbox
except ImportError:
    DockerSandbox = None
    
try:
    from anti_evasion import AntiEvasionDetector
except ImportError:
    AntiEvasionDetector = None
    
try:
    from threat_intelligence import MultiSourceThreatIntelligence
except ImportError:
    MultiSourceThreatIntelligence = None
    
try:
    from threat_dashboard import ThreatLandscapeDashboard
    dashboard = ThreatLandscapeDashboard()
except ImportError:
    ThreatLandscapeDashboard = None
    dashboard = None

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log'
)
logger = logging.getLogger('Malware-Detector')

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload size

# Configuration
UPLOAD_FOLDER = 'uploads'
RESULTS_FOLDER = 'results'
BATCH_FOLDER = 'batch_uploads'
MODEL_PATH = 'ML_model/malwareclassifier-V2.pkl'
ALLOWED_EXTENSIONS = {
    'executable': {'exe', 'dll', 'sys', 'ocx', 'com', 'scr', 'msi', 'bin'},
    'document': {'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'rtf', 'txt'},
    'script': {'js', 'py', 'ps1', 'vbs', 'bat', 'sh', 'cmd', 'jar'},
    'archive': {'zip', 'rar', '7z', 'tar', 'gz'},
    'malware': {'class', 'apk', 'dex', 'elf', 'dmg', 'pkg'}  # Added common malware file types
}

# Create required directories
for folder in [UPLOAD_FOLDER, RESULTS_FOLDER, BATCH_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Initialize components with fallback options
def init_components():
    """Initialize all system components"""
    components = {
        'ml_model': {'status': 'unavailable', 'instance': None, 'error': None},
        'feature_extractor': {'status': 'unavailable', 'instance': None, 'error': None},
        'malware_type_detector': {'status': 'unavailable', 'instance': None, 'error': None},
        'document_analyzer': {'status': 'unavailable', 'instance': None, 'error': None},
        'vt_scanner': {'status': 'unavailable', 'instance': None, 'error': None},
        'dynamic_analyzer': {'status': 'unavailable', 'instance': None, 'error': None},
        'batch_processor': {'status': 'unavailable', 'instance': None, 'error': None},
        'model_explainer': {'status': 'unavailable', 'instance': None, 'error': None},
        'realtime_monitor': {'status': 'unavailable', 'instance': None, 'error': None}
    }
    
    # Try to initialize ML model
    try:
        import joblib
        components['ml_model']['instance'] = joblib.load(MODEL_PATH)
        components['ml_model']['status'] = 'available'
        logger.info("ML model loaded successfully")
    except Exception as e:
        logger.error(f"Error loading ML model: {e}")
        components['ml_model']['error'] = str(e)
    
    # Try to initialize feature extractor
    try:
        import feature_extraction
        components['feature_extractor']['instance'] = feature_extraction
        components['feature_extractor']['status'] = 'available'
        logger.info("Feature extractor loaded successfully")
    except Exception as e:
        logger.error(f"Error loading feature extractor: {e}")
        components['feature_extractor']['error'] = str(e)
    
    # Try to initialize malware type detector
    try:
        from malware_types import MalwareTypeDetector
        components['malware_type_detector']['instance'] = MalwareTypeDetector()
        components['malware_type_detector']['status'] = 'available'
        logger.info("Malware type detector loaded successfully")
    except Exception as e:
        logger.error(f"Error loading malware type detector: {e}")
        components['malware_type_detector']['error'] = str(e)
    
    # Try to initialize document analyzer
    try:
        from document_analyzer import DocumentAnalyzer
        components['document_analyzer']['instance'] = DocumentAnalyzer()
        components['document_analyzer']['status'] = 'available'
        logger.info("Document analyzer loaded successfully")
    except Exception as e:
        logger.error(f"Error loading document analyzer: {e}")
        components['document_analyzer']['error'] = str(e)
    
    # Try to initialize VirusTotal scanner
    try:
        from vt_api import VirusTotalScanner
        # Use hardcoded API key if environment variable not set
        vt_api_key = os.environ.get('VT_API_KEY') or '9945c44ec7c6e131d6e6c49bf6185bd7d51b82a8a56204a7711c5199eed27675'
        vt_scanner = VirusTotalScanner(api_key=vt_api_key)
        if vt_scanner.enabled:
            components['vt_scanner']['instance'] = vt_scanner
            components['vt_scanner']['status'] = 'available'
            logger.info("VirusTotal scanner loaded successfully with hardcoded API key")
        else:
            components['vt_scanner']['error'] = "VirusTotal API key not configured"
            logger.warning("VirusTotal scanner initialized but API key not configured")
    except Exception as e:
        logger.error(f"Error loading VirusTotal scanner: {e}")
        components['vt_scanner']['error'] = str(e)
    
    # Try to initialize dynamic analyzer
    try:
        from dynamic_analysis import DynamicAnalyzer
        components['dynamic_analyzer']['instance'] = DynamicAnalyzer()
        components['dynamic_analyzer']['status'] = 'available'
        logger.info("Dynamic analyzer loaded successfully")
    except Exception as e:
        logger.error(f"Error loading dynamic analyzer: {e}")
        components['dynamic_analyzer']['error'] = str(e)
    
    # Try to initialize batch processor
    try:
        from batch_processor import BatchProcessor
        components['batch_processor']['instance'] = BatchProcessor(output_dir=RESULTS_FOLDER)
        components['batch_processor']['status'] = 'available'
        logger.info("Batch processor loaded successfully")
    except Exception as e:
        logger.error(f"Error loading batch processor: {e}")
        components['batch_processor']['error'] = str(e)
    
    # Try to initialize model explainer
    try:
        from model_explainer import ModelExplainer
        components['model_explainer']['instance'] = ModelExplainer(model_path=MODEL_PATH)
        components['model_explainer']['status'] = 'available'
        logger.info("Model explainer loaded successfully")
    except Exception as e:
        logger.error(f"Error loading model explainer: {e}")
        components['model_explainer']['error'] = str(e)
    
    # Try to initialize realtime monitor
    try:
        from realtime_monitor import RealtimeMonitor
        components['realtime_monitor']['instance'] = RealtimeMonitor()
        components['realtime_monitor']['status'] = 'available'
        logger.info("Realtime monitor loaded successfully")
    except Exception as e:
        logger.error(f"Error loading realtime monitor: {e}")
        components['realtime_monitor']['error'] = str(e)
    
    # Initialize advanced components
    if DockerSandbox:
        components['docker_sandbox'] = {'status': 'available', 'instance': DockerSandbox, 'error': None}
        logger.info("Docker sandbox initialized")
    else:
        components['docker_sandbox'] = {'status': 'unavailable', 'instance': None, 'error': 'Docker not available'}
            
    if AntiEvasionDetector:
        try:
            components['anti_evasion'] = {'status': 'available', 'instance': AntiEvasionDetector(), 'error': None}
            logger.info("Anti-evasion detector initialized")
        except Exception as e:
            components['anti_evasion'] = {'status': 'unavailable', 'instance': None, 'error': str(e)}
    else:
        components['anti_evasion'] = {'status': 'unavailable', 'instance': None, 'error': 'Anti-evasion module not available'}
            
    if MultiSourceThreatIntelligence:
        try:
            components['threat_intel'] = {'status': 'available', 'instance': MultiSourceThreatIntelligence(), 'error': None}
            logger.info("Multi-source threat intelligence initialized")
        except Exception as e:
            components['threat_intel'] = {'status': 'unavailable', 'instance': None, 'error': str(e)}
    else:
        components['threat_intel'] = {'status': 'unavailable', 'instance': None, 'error': 'Threat intelligence module not available'}
    
    if dashboard:
        try:
            dashboard.start_monitoring()
            components['threat_dashboard'] = {'status': 'available', 'instance': dashboard, 'error': None}
            logger.info("Threat dashboard initialized")
        except Exception as e:
            components['threat_dashboard'] = {'status': 'unavailable', 'instance': None, 'error': str(e)}
    else:
        components['threat_dashboard'] = {'status': 'unavailable', 'instance': None, 'error': 'Dashboard module not available'}
        
    return components

# Initialize components
COMPONENTS = init_components()

def _make_json_serializable_dict(obj):
    """Convert nested dict/list structure to JSON-serializable format"""
    import numpy as np
    
    if isinstance(obj, dict):
        return {key: _make_json_serializable_dict(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_make_json_serializable_dict(item) for item in obj]
    elif isinstance(obj, tuple):
        return list(_make_json_serializable_dict(item) for item in obj)
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (np.bool_, bool)):
        return bool(obj)  # Ensure Python bool
    elif isinstance(obj, np.str_):
        return str(obj)
    elif obj is None:
        return None
    elif isinstance(obj, (int, float, str)):
        return obj
    else:
        # For any other type, convert to string as fallback
        return str(obj)

def safe_filename(filename):
    """Create a safe filename for Windows and cross-platform compatibility"""
    # Use secure_filename and additional Windows-specific sanitization
    safe_name = secure_filename(filename)
    
    # Remove/replace problematic characters for Windows
    unsafe_chars = ['<', '>', ':', '"', '|', '?', '*']
    for char in unsafe_chars:
        safe_name = safe_name.replace(char, '_')
    
    # Ensure filename is not empty and not too long
    if not safe_name or safe_name.isspace():
        safe_name = 'unknown_file'
    
    # Limit filename length
    if len(safe_name) > 200:
        name_part, ext = os.path.splitext(safe_name)
        safe_name = name_part[:200-len(ext)] + ext
    
    return safe_name

def allowed_file(filename):
    """Check if a file is allowed based on its extension"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    # Fix: Use set.union() instead of sum() to combine sets
    all_extensions = set()
    for extensions in ALLOWED_EXTENSIONS.values():
        all_extensions.update(extensions)
    return ext in all_extensions

def get_file_type(file_path):
    """Get file type using magic library with fallback to mimetypes"""
    try:
        if magic:
            # Try using python-magic
            try:
                mime_type = magic.from_file(file_path, mime=True)
                return mime_type
            except Exception:
                # Fallback to file extension-based detection
                pass
        
        # Use mimetypes as fallback
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or 'application/octet-stream'
    except Exception as e:
        logger.warning(f"Error detecting file type for {file_path}: {e}")
        return 'application/octet-stream'

def get_file_category(filename):
    """Determine the file category based on extension"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    for category, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return category
    return "unknown"

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        return None

def analyze_file(file_path):
    """Analyze a file using all available components"""
    try:
        filename = os.path.basename(file_path)
        file_category = get_file_category(filename)
        file_hash = calculate_hash(file_path)
        
        results = {
            "filename": filename,
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "file_hash": file_hash,
            "file_category": file_category,
            "is_malware": False,
            "confidence": 0,
            "malware_type": "Unknown",
            "risk_score": 0,
            "timestamp": datetime.now().isoformat(),
            "details": {}
        }
        
        # ML model analysis (for executables)
        if file_category == "executable" and 'ml_model' in COMPONENTS and COMPONENTS['ml_model']['status'] == 'available' and COMPONENTS['ml_model']['instance']:
            try:
                # Use feature extractor if available, otherwise use fallback
                if 'feature_extractor' in COMPONENTS and COMPONENTS['feature_extractor']['status'] == 'available':
                    features = COMPONENTS['feature_extractor']['instance'].extract_features(file_path)
                else:
                    # Use fallback feature extraction
                    features = fallback_extract_features(file_path)
                
                prediction = COMPONENTS['ml_model']['instance'].predict(features)[0]
                
                if prediction == 1:
                    results["is_malware"] = True
                    results["confidence"] = 0.85  # Default confidence for ML model
                
                # Try to get probability if model supports it
                if hasattr(COMPONENTS['ml_model']['instance'], 'predict_proba'):
                    proba = COMPONENTS['ml_model']['instance'].predict_proba(features)[0, 1]
                    results["confidence"] = proba
                
                results["details"]["ml_model"] = {
                    "prediction": int(prediction),
                    "probability": float(results["confidence"])
                }
                
                # Add feature importance if model explainer is available
                if 'model_explainer' in COMPONENTS and COMPONENTS['model_explainer']['status'] == 'available' and COMPONENTS['model_explainer']['instance']:
                    try:
                        explanation = COMPONENTS['model_explainer']['instance'].explain_prediction(file_path)
                        results["details"]["ml_model"]["explanation"] = explanation
                    except Exception as e:
                        logger.error(f"Error getting model explanation: {e}")
            except Exception as e:
                logger.error(f"Error in ML model analysis: {e}")
                # Use fallback malware detection
                try:
                    is_suspicious = fallback_detect_malware(file_path)
                    if is_suspicious:
                        results["is_malware"] = True
                        results["confidence"] = 0.6
                        results["malware_type"] = "Suspicious"
                    results["details"]["ml_model"] = {"fallback_used": True, "suspicious": is_suspicious}
                except Exception:
                    results["details"]["ml_model"] = {"error": str(e)}
        
        # Malware type detection
        if 'malware_type_detector' in COMPONENTS and COMPONENTS['malware_type_detector']['status'] == 'available' and COMPONENTS['malware_type_detector']['instance']:
            try:
                type_result = COMPONENTS['malware_type_detector']['instance'].detect_malware_type(file_path)
                
                if type_result["confidence"] > 0.5:
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], type_result["confidence"])
                    results["malware_type"] = type_result["detected_type"]
                
                results["details"]["malware_type"] = type_result
            except Exception as e:
                logger.error(f"Error in malware type detection: {e}")
                results["details"]["malware_type"] = {"error": str(e)}
        
        # Document analysis (for documents)
        if file_category == "document" and 'document_analyzer' in COMPONENTS and COMPONENTS['document_analyzer']['status'] == 'available' and COMPONENTS['document_analyzer']['instance']:
            try:
                doc_result = COMPONENTS['document_analyzer']['instance'].analyze_document(file_path)
                
                # Update risk score
                doc_risk_score = doc_result.get("risk_score", {}).get("score", 0)
                results["risk_score"] = max(results["risk_score"], doc_risk_score)
                
                # If high risk or suspicious objects found, consider it potential malware
                if doc_risk_score > 70 or doc_result.get("has_suspicious_objects", False):
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], doc_risk_score / 100)
                
                results["details"]["document_analysis"] = doc_result
            except Exception as e:
                logger.error(f"Error in document analysis: {e}")
                results["details"]["document_analysis"] = {"error": str(e)}
        
        # Dynamic analysis (for executables)
        if file_category == "executable" and 'dynamic_analyzer' in COMPONENTS and COMPONENTS['dynamic_analyzer']['status'] == 'available' and COMPONENTS['dynamic_analyzer']['instance']:
            try:
                # Dynamic analysis can be resource-intensive, so we'll do it only for suspicious files
                # or if specifically requested
                if results["is_malware"] or results["risk_score"] > 50:
                    dyn_result = COMPONENTS['dynamic_analyzer']['instance'].analyze_file(file_path)
                    
                    # Update risk score and confidence
                    dyn_risk_score = dyn_result.get("risk_score", {}).get("score", 0)
                    results["risk_score"] = max(results["risk_score"], dyn_risk_score)
                    
                    if dyn_risk_score > 70:
                        results["is_malware"] = True
                        results["confidence"] = max(results["confidence"], dyn_risk_score / 100)
                    
                    # Update malware type if found
                    if 'malware_type_indicators' in dyn_result:
                        malware_type = dyn_result['malware_type_indicators'].get('likely_type', '')
                        if malware_type and malware_type != "Unknown" and results["malware_type"] == "Unknown":
                            results["malware_type"] = malware_type
                    
                    results["details"]["dynamic_analysis"] = dyn_result
            except Exception as e:
                logger.error(f"Error in dynamic analysis: {e}")
                results["details"]["dynamic_analysis"] = {"error": str(e)}
        
        # Advanced sandbox analysis
        if 'docker_sandbox' in COMPONENTS and COMPONENTS['docker_sandbox']['status'] == 'available' and file_category == "executable":
            try:
                with COMPONENTS['docker_sandbox']['instance']() as sandbox:
                    sandbox_result = sandbox.analyze_file(file_path, analysis_type="basic")
                    
                    if sandbox_result.get('security_analysis', {}).get('suspicious_network_activity', False):
                        results["is_malware"] = True
                        results["confidence"] = max(results["confidence"], 0.8)
                        results["malware_type"] = "Network Trojan"
                    
                    results["details"]["sandbox"] = sandbox_result
            except Exception as e:
                logger.error(f"Error in sandbox analysis: {e}")
                results["details"]["sandbox"] = {"error": str(e)}
        
        # Anti-evasion analysis
        if 'anti_evasion' in COMPONENTS and COMPONENTS['anti_evasion']['status'] == 'available':
            try:
                evasion_result = COMPONENTS['anti_evasion']['instance'].detect_evasion_techniques(file_path)
                
                if evasion_result.get('risk_score', 0) > 50:
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], evasion_result['risk_score'] / 100)
                    if results["malware_type"] == "Unknown":
                        results["malware_type"] = "Evasive Malware"
                
                results["details"]["anti_evasion"] = evasion_result
            except Exception as e:
                logger.error(f"Error in anti-evasion analysis: {e}")
                results["details"]["anti_evasion"] = {"error": str(e)}
        
        # Multi-source threat intelligence
        if 'threat_intel' in COMPONENTS and COMPONENTS['threat_intel']['status'] == 'available':
            try:
                intel_result = COMPONENTS['threat_intel']['instance'].analyze_file_multi_source(file_path)
                
                if intel_result.get('aggregated_verdict') == 'malicious':
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], intel_result.get('confidence_score', 0))
                    if intel_result.get('threat_family') != 'unknown':
                        results["malware_type"] = intel_result['threat_family']
                
                results["details"]["threat_intelligence"] = intel_result
            except Exception as e:
                logger.error(f"Error in threat intelligence analysis: {e}")
                results["details"]["threat_intelligence"] = {"error": str(e)}
        
        # VirusTotal analysis (optional)
        if 'vt_scanner' in COMPONENTS and COMPONENTS['vt_scanner']['status'] == 'available' and COMPONENTS['vt_scanner']['instance']:
            try:
                vt_result = COMPONENTS['vt_scanner']['instance'].scan_file(file_path)
                
                if vt_result.get("positives", 0) > 3:  # Arbitrary threshold
                    results["is_malware"] = True
                    results["confidence"] = max(results["confidence"], vt_result.get("positives", 0) / vt_result.get("total", 100))
                    
                    # Get malware type from VT if not determined yet
                    if results["malware_type"] == "Unknown" and 'scans' in vt_result:
                        for engine, scan in vt_result['scans'].items():
                            if scan.get('detected', False):
                                result_text = scan.get('result', '').lower()
                                malware_types = ['trojan', 'backdoor', 'spyware', 'ransom', 'worm', 'virus']
                                for t in malware_types:
                                    if t in result_text:
                                        results["malware_type"] = t.capitalize()
                                        break
                                if results["malware_type"] != "Unknown":
                                    break
                
                results["details"]["virustotal"] = vt_result
            except Exception as e:
                logger.error(f"Error in VirusTotal analysis: {e}")
                results["details"]["virustotal"] = {"error": str(e)}
        
        # If no specific analysis was performed, at least do basic analysis
        if not results["details"]:
            # Perform basic file analysis
            try:
                is_suspicious = fallback_detect_malware(file_path)
                if is_suspicious:
                    results["is_malware"] = True
                    results["confidence"] = 0.6
                    results["malware_type"] = "Suspicious"
                    results["risk_score"] = 65
                
                results["details"]["basic_analysis"] = {
                    "method": "pattern_matching",
                    "suspicious": is_suspicious,
                    "file_type": get_file_type(file_path),
                    "file_size": os.path.getsize(file_path)
                }
            except Exception as e:
                logger.error(f"Error in basic analysis: {e}")
                results["details"]["basic_analysis"] = {"error": str(e)}
        
        # Final risk assessment if not determined by other methods
        if not results["is_malware"] and results["risk_score"] > 70:
            results["is_malware"] = True
            results["confidence"] = max(results["confidence"], results["risk_score"] / 100)
        
        # Save result to file
        result_path = os.path.join(RESULTS_FOLDER, f"{file_hash}.json")
        with open(result_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
        
    except Exception as e:
        logger.error(f"Error analyzing file {file_path}: {e}")
        return {
            "error": str(e),
            "filename": os.path.basename(file_path),
            "is_malware": False
        }

# Flask routes
@app.route('/test')
def test_route():
    """Simple test route"""
    return "Cerberus AI Cybershield is working!"

@app.route('/test-analysis')
def test_analysis():
    """Test the analysis function"""
    test_file = os.path.join(UPLOAD_FOLDER, 'test.txt')
    if os.path.exists(test_file):
        try:
            result = analyze_file(test_file)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "Test file not found"}), 404

@app.route('/')
def index():
    """Render the main page"""
    # Map component names to match template expectations
    available_features = {
        'ml_model': COMPONENTS.get('ml_model', {}).get('status') == 'available',
        'docker_sandbox': COMPONENTS.get('docker_sandbox', {}).get('status') == 'available',
        'anti_evasion': COMPONENTS.get('anti_evasion', {}).get('status') == 'available',
        'threat_intel': COMPONENTS.get('threat_intel', {}).get('status') == 'available',
        'document': COMPONENTS.get('document_analyzer', {}).get('status') == 'available',  # Map document_analyzer to document
        'dashboard': True  # Dashboard is always considered available
    }
    return render_template('modern_index.html', features=available_features)

@app.route('/dashboard')
def dashboard():
    """Render the threat intelligence dashboard - DISABLED (non-functional)"""
    # Dashboard feature disabled due to non-functional state
    # return render_template('threat_dashboard.html')
    return render_template('index.html', error="Dashboard feature is currently under development")

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a single uploaded file using BatchProcessor (same as working Streamlit app)"""
    logger.info("=== ANALYZE ROUTE CALLED ===")
    
    if 'file' not in request.files:
        logger.error("No file in request")
        return render_template('modern_index.html', error="No file provided")

    file = request.files['file']
    logger.info(f"File received: {file.filename}")
    
    if file.filename == '':
        logger.error("Empty filename")
        return render_template('modern_index.html', error="No file selected")

    if file and allowed_file(file.filename):
        try:
            # Clean filename and save file
            filename = safe_filename(file.filename)
            # Normalize path for Windows compatibility
            file_path = os.path.normpath(os.path.join(UPLOAD_FOLDER, filename))
            logger.info(f"Saving file to: {file_path}")
            
            # Ensure upload directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            file.save(file_path)
            logger.info(f"File saved successfully: {file_path}")
            
            # Use BatchProcessor like the working Streamlit app
            if 'batch_processor' in COMPONENTS and COMPONENTS['batch_processor']['status'] == 'available' and COMPONENTS['batch_processor']['instance']:
                logger.info("Using BatchProcessor for analysis")
                
                # Create timestamp for batch directory (required by BatchProcessor)
                import time
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                batch_dir = os.path.join(RESULTS_FOLDER, f"single_{timestamp}")
                os.makedirs(batch_dir, exist_ok=True)
                logger.info(f"Created batch directory: {batch_dir}")
                
                # Process the file using the same method as Streamlit
                logger.info("Starting BatchProcessor analysis...")
                result = COMPONENTS['batch_processor']['instance']._process_single_file(file_path, batch_dir)
                logger.info(f"BatchProcessor analysis complete: {result}")
                
                # Format result for web interface
                web_result = {
                    "filename": result.get('file_name', filename),
                    "file_hash": result.get('file_hash', ''),
                    "is_malware": result.get('is_malware', False),
                    "confidence": result.get('confidence', 0),
                    "malware_type": result.get('malware_type', 'Unknown'),
                    "risk_score": result.get('risk_score', 0),
                    "analysis_method": result.get('analysis_method', ''),
                    "processing_time": result.get('processing_time', 0),
                    "timestamp": datetime.now().isoformat(),
                    "detailed_results": result.get('detailed_results', {})
                }
                
                logger.info(f"Successfully analyzed {filename} using BatchProcessor")
                return jsonify(web_result)
            else:
                # Fallback to simple analysis if BatchProcessor unavailable
                logger.warning("BatchProcessor unavailable, using fallback analysis")
                logger.info(f"Component status: {COMPONENTS.get('batch_processor', {}).get('status', 'missing')}")
                
                result = {
                    "filename": filename,
                    "file_hash": calculate_hash(file_path),
                    "is_malware": fallback_detect_malware(file_path),
                    "confidence": 0.6 if fallback_detect_malware(file_path) else 0.2,
                    "malware_type": "Suspicious" if fallback_detect_malware(file_path) else "Clean",
                    "risk_score": 65 if fallback_detect_malware(file_path) else 15,
                    "analysis_method": "Fallback",
                    "processing_time": 0.5,
                    "timestamp": datetime.now().isoformat(),
                    "detailed_results": {"fallback_analysis": {"method": "pattern_matching"}}
                }
                logger.info(f"Fallback analysis complete: {result}")
                return jsonify(result)
                
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            
            # Clean up file if it was partially created
            try:
                if 'file_path' in locals() and os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Cleaned up partial file: {file_path}")
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up file: {cleanup_error}")
            
            return jsonify({"error": f"Error processing file: {str(e)}"}), 500
    else:
        logger.error(f"File type not allowed: {file.filename}")
        return jsonify({"error": "Unsupported file type"}), 400

@app.route('/batch', methods=['GET', 'POST'])
def batch_analysis():
    """Handle batch analysis requests"""
    if request.method == 'POST':
        if 'files[]' not in request.files:
            return render_template('batch.html', error="No files provided")
        
        files = request.files.getlist('files[]')
        
        if not files or files[0].filename == '':
            return render_template('batch.html', error="No files selected")
        
        # Get processing options from form
        memory_limit = request.form.get('memory_limit', type=int, default=500)  # Default 500MB
        large_file_threshold = request.form.get('large_file_threshold', type=int, default=50)  # Default 50MB
        
        # Save files temporarily
        saved_files = []
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        batch_dir = os.path.join(BATCH_FOLDER, timestamp)
        os.makedirs(batch_dir, exist_ok=True)
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = safe_filename(file.filename)
                file_path = os.path.normpath(os.path.join(batch_dir, filename))
                file.save(file_path)
                saved_files.append(file_path)
        
        if saved_files:
            # Process files immediately and show results
            if 'batch_processor' in COMPONENTS and COMPONENTS['batch_processor']['status'] == 'available' and COMPONENTS['batch_processor']['instance']:
                try:
                    # Create results directory
                    results_dir = os.path.join(RESULTS_FOLDER, f"batch_{timestamp}")
                    os.makedirs(results_dir, exist_ok=True)
                    
                    # Process each file
                    batch_results = []
                    malware_count = 0
                    clean_count = 0
                    
                    for file_path in saved_files:
                        logger.info(f"Processing file: {file_path}")
                        result = COMPONENTS['batch_processor']['instance']._process_single_file(file_path, results_dir)
                        
                        # Count malware vs clean
                        if result.get('is_malware', False):
                            malware_count += 1
                        else:
                            clean_count += 1
                            
                        batch_results.append(result)
                    
                    # Create summary
                    summary = {
                        'total_files': len(batch_results),
                        'malware_files': malware_count,
                        'clean_files': clean_count,
                        'timestamp': timestamp,
                        'results_dir': results_dir
                    }
                    
                    # Render results page
                    return render_template('batch_results.html', 
                                         results=batch_results, 
                                         summary=summary,
                                         timestamp=timestamp)
                    
                except Exception as e:
                    logger.error(f"Error in batch processing: {e}")
                    return render_template('batch.html', error=f"Batch processing failed: {str(e)}")
            else:
                return render_template('batch.html', error="Batch processor not available")
        else:
            return render_template('batch.html', error="No valid files to process")
    
    # GET request - show upload form
    return render_template('batch.html')

@app.route('/batch/export/<timestamp>/<format>')
def export_batch_results(timestamp, format):
    """Export batch analysis results in various formats"""
    try:
        # Find the results directory
        results_dir = os.path.join(RESULTS_FOLDER, f"batch_{timestamp}")
        if not os.path.exists(results_dir):
            return jsonify({"error": "Results not found"}), 404
        
        # Collect all result files
        result_files = []
        for file in os.listdir(results_dir):
            if file.endswith('.json') and file != 'summary.json':
                file_path = os.path.join(results_dir, file)
                try:
                    with open(file_path, 'r') as f:
                        result_data = json.load(f)
                        result_files.append(result_data)
                except Exception as e:
                    logger.error(f"Error reading result file {file}: {e}")
        
        if format.lower() == 'csv':
            # Export as CSV
            from io import StringIO
            import csv
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write headers
            headers = ['Filename', 'File Hash', 'Is Malware', 'Confidence', 
                      'Malware Type', 'Risk Score', 'Analysis Method', 'Processing Time']
            writer.writerow(headers)
            
            # Write data
            for result in result_files:
                writer.writerow([
                    result.get('file_name', ''),
                    result.get('file_hash', ''),
                    result.get('is_malware', False),
                    result.get('confidence', 0),
                    result.get('malware_type', ''),
                    result.get('risk_score', 0),
                    result.get('analysis_method', ''),
                    result.get('processing_time', 0)
                ])
            
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=batch_results_{timestamp}.csv'
            return response
            
        elif format.lower() == 'json':
            # Export as JSON
            response = make_response(json.dumps(result_files, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=batch_results_{timestamp}.json'
            return response
            
        elif format.lower() == 'pdf':
            # For PDF export, return a simple message for now
            return jsonify({"message": "PDF export feature coming soon!"})
            
        else:
            return jsonify({"error": "Unsupported format"}), 400
            
    except Exception as e:
        logger.error(f"Error exporting batch results: {e}")
        return jsonify({"error": str(e)}), 500
    
    # GET request - show the batch upload form
    return render_template('batch.html')

@app.route('/realtime', methods=['GET', 'POST'])
def realtime_monitoring():
    """Manage real-time monitoring"""
    global COMPONENTS
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start':
            if 'realtime_monitor' in COMPONENTS and COMPONENTS['realtime_monitor']['status'] == 'available' and COMPONENTS['realtime_monitor']['instance']:
                if COMPONENTS['realtime_monitor']['instance'].is_running is None or not COMPONENTS['realtime_monitor']['instance'].is_running:
                    # Get directories to monitor
                    directories = request.form.get('directories', '')
                    watch_dirs = [d.strip() for d in directories.split(',') if d.strip()]
                    
                    # Start monitoring
                    COMPONENTS['realtime_monitor']['instance'].start_monitoring(watch_directories=watch_dirs)
                    
                    return render_template('realtime.html', 
                                          status="running", 
                                          dirs=watch_dirs,
                                          monitor=COMPONENTS['realtime_monitor']['instance'])
                else:
                    return render_template('realtime.html', 
                                          status="already_running",
                                          monitor=COMPONENTS['realtime_monitor']['instance'],
                                          dirs=COMPONENTS['realtime_monitor']['instance'].watch_directories)
            else:
                return render_template('realtime.html', 
                                      error="Real-time monitoring is not available")
        
        elif action == 'stop':
            if COMPONENTS['realtime_monitor']['instance'] and COMPONENTS['realtime_monitor']['instance'].is_running:
                COMPONENTS['realtime_monitor']['instance'].stop_monitoring()
                return render_template('realtime.html', 
                                      status="stopped",
                                      dirs=[])
            else:
                return render_template('realtime.html', 
                                      status="not_running")
        
        elif action == 'status':
            if COMPONENTS['realtime_monitor']['instance']:
                status_report = COMPONENTS['realtime_monitor']['instance'].get_status_report()
                return render_template('realtime.html', 
                                      status="running" if COMPONENTS['realtime_monitor']['instance'].is_running else "stopped",
                                      report=status_report,
                                      dirs=COMPONENTS['realtime_monitor']['instance'].watch_directories,
                                      monitor=COMPONENTS['realtime_monitor']['instance'])
            else:
                return render_template('realtime.html', 
                                      status="not_initialized")
    
    # GET request - show the real-time monitoring page
    if COMPONENTS['realtime_monitor']['instance']:
        status = "running" if COMPONENTS['realtime_monitor']['instance'].is_running else "stopped"
        report = COMPONENTS['realtime_monitor']['instance'].get_status_report() if COMPONENTS['realtime_monitor']['instance'].is_running else None
        return render_template('realtime.html', 
                              status=status,
                              report=report,
                              dirs=COMPONENTS['realtime_monitor']['instance'].watch_directories if COMPONENTS['realtime_monitor']['instance'].is_running else [],
                              monitor=COMPONENTS['realtime_monitor']['instance'])
    else:
        return render_template('realtime.html', 
                              status="not_initialized")

def _make_json_serializable_dict(obj):
    """Convert object to JSON-serializable format"""
    if isinstance(obj, dict):
        return {key: _make_json_serializable_dict(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_make_json_serializable_dict(item) for item in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    elif isinstance(obj, np.str_):
        return str(obj)
    else:
        return obj

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for file analysis using BatchProcessor"""
    logger.info("=== API ANALYZE ROUTE CALLED ===")
    
    if 'file' not in request.files:
        logger.error("API: No file in request")
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    logger.info(f"API: File received: {file.filename}")
    
    if file.filename == '':
        logger.error("API: Empty filename")
        return jsonify({"error": "No file selected"}), 400

    if file and allowed_file(file.filename):
        try:
            # Clean filename and save file
            filename = safe_filename(file.filename)
            # Normalize path for Windows compatibility
            file_path = os.path.normpath(os.path.join(UPLOAD_FOLDER, filename))
            logger.info(f"API: Saving file to: {file_path}")
            
            # Ensure upload directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            file.save(file_path)
            logger.info(f"API: File saved successfully")

            # Use BatchProcessor like the working Streamlit app
            if 'batch_processor' in COMPONENTS and COMPONENTS['batch_processor']['status'] == 'available' and COMPONENTS['batch_processor']['instance']:
                logger.info("API: Using BatchProcessor for analysis")
                
                # Create timestamp for batch directory
                import time
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                batch_dir = os.path.join(RESULTS_FOLDER, f"api_{timestamp}")
                os.makedirs(batch_dir, exist_ok=True)
                logger.info(f"API: Created batch directory: {batch_dir}")
                
                # Process the file using BatchProcessor
                logger.info("API: Starting BatchProcessor analysis...")
                result = COMPONENTS['batch_processor']['instance']._process_single_file(file_path, batch_dir)
                logger.info(f"API: BatchProcessor analysis complete: {type(result)}")
                
                # Return JSON response in API format
                api_result = {
                    "status": "success",
                    "filename": result.get('file_name', filename),
                    "file_hash": result.get('file_hash', ''),
                    "is_malware": bool(result.get('is_malware', False)),  # Ensure it's Python bool
                    "confidence": float(result.get('confidence', 0)),  # Ensure it's Python float
                    "malware_type": str(result.get('malware_type', 'Unknown')),  # Ensure it's Python str
                    "risk_score": int(result.get('risk_score', 0)) if isinstance(result.get('risk_score', 0), (int, float)) else 0,  # Ensure it's Python int
                    "analysis_method": str(result.get('analysis_method', '')),
                    "processing_time": float(result.get('processing_time', 0)),
                    "timestamp": datetime.now().isoformat(),
                    "detailed_results": _make_json_serializable_dict(result.get('detailed_results', {}))
                }
                
                logger.info(f"API: Returning successful result")
                return jsonify(api_result)
            else:
                # Fallback analysis
                logger.warning("API: BatchProcessor unavailable, using fallback")
                logger.info(f"API: Component status: {COMPONENTS.get('batch_processor', {}).get('status', 'missing')}")
                
                result = {
                    "status": "success",
                    "filename": filename,
                    "file_hash": calculate_hash(file_path),
                    "is_malware": fallback_detect_malware(file_path),
                    "confidence": 0.6,
                    "malware_type": "Suspicious",
                    "analysis_method": "Fallback",
                    "timestamp": datetime.now().isoformat()
                }
                logger.info(f"API: Fallback analysis complete")
                return jsonify(result)
                
        except Exception as e:
            logger.error(f"API error: {e}")
            import traceback
            logger.error(f"API: Full traceback: {traceback.format_exc()}")
            
            # Clean up file if it was partially created
            try:
                if 'file_path' in locals() and os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"API: Cleaned up partial file: {file_path}")
            except Exception as cleanup_error:
                logger.error(f"API: Error cleaning up file: {cleanup_error}")
            
            return jsonify({"error": str(e)}), 500
    else:
        logger.error(f"API: File type not allowed: {file.filename}")
        return jsonify({"error": "Unsupported file type"}), 400

@app.route('/api/scan-url', methods=['POST'])
def api_scan_url():
    """API endpoint for URL scanning"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    url = data['url']
    
    try:
        # Basic URL analysis
        result = {
            'url': url,
            'is_malware': False,
            'threat_score': 0,
            'malware_type': 'Unknown',
            'confidence': 0,
            'sources': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Use threat intelligence if available
        if 'threat_intel' in COMPONENTS and COMPONENTS['threat_intel']['status'] == 'available':
            try:
                # For URL scanning, we'll simulate file analysis
                # In a real implementation, you'd fetch and analyze the webpage
                intel_result = {'threat_score': 25, 'is_malware': False}
                result.update(intel_result)
            except Exception as e:
                logger.error(f"Threat intelligence error: {e}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"URL scan error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-hostname', methods=['POST'])
def api_scan_hostname():
    """API endpoint for hostname scanning"""
    data = request.get_json()
    
    if not data or 'hostname' not in data:
        return jsonify({"error": "No hostname provided"}), 400
    
    hostname = data['hostname']
    
    try:
        # Basic hostname analysis
        result = {
            'hostname': hostname,
            'is_malware': False,
            'threat_score': 15,  # Default low score
            'confidence': 0.3,
            'timestamp': datetime.now().isoformat()
        }
        
        # Simple heuristics for demonstration
        suspicious_patterns = ['malware', 'phish', 'scam', 'fake', 'suspicious']
        if any(pattern in hostname.lower() for pattern in suspicious_patterns):
            result['is_malware'] = True
            result['threat_score'] = 85
            result['confidence'] = 0.9
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Hostname scan error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def api_status():
    """API endpoint to get system status"""
    status = {
        "components": {k: (v['status'] == 'available') for k, v in COMPONENTS.items()},
        "realtime_monitoring": False
    }
    
    if COMPONENTS['realtime_monitor']['status'] == 'available' and COMPONENTS['realtime_monitor']['instance']:
        status["realtime_monitoring"] = COMPONENTS['realtime_monitor']['instance'].is_running
        
    return jsonify(status)

@app.route('/api/realtime/start', methods=['POST'])
def api_realtime_start():
    """API endpoint to start real-time monitoring"""
    global COMPONENTS
    
    if 'realtime_monitor' not in COMPONENTS or COMPONENTS['realtime_monitor']['status'] != 'available' or not COMPONENTS['realtime_monitor']['instance']:
        return jsonify({"error": "Real-time monitoring is not available"}), 400
    
    if COMPONENTS['realtime_monitor']['instance'] and COMPONENTS['realtime_monitor']['instance'].is_running:
        return jsonify({"error": "Real-time monitoring is already running"}), 400
    
    try:
        # Get directories from JSON
        data = request.get_json() or {}
        watch_dirs = data.get('directories', [])
        
        # Start monitoring
        COMPONENTS['realtime_monitor']['instance'].start_monitoring(watch_directories=watch_dirs)
        
        return jsonify({"status": "success", "message": "Real-time monitoring started"})
    except Exception as e:
        logger.error(f"API error starting monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/realtime/stop', methods=['POST'])
def api_realtime_stop():
    """API endpoint to stop real-time monitoring"""
    global COMPONENTS
    
    if not COMPONENTS['realtime_monitor']['instance'] or not COMPONENTS['realtime_monitor']['instance'].is_running:
        return jsonify({"error": "Real-time monitoring is not running"}), 400
    
    try:
        COMPONENTS['realtime_monitor']['instance'].stop_monitoring()
        return jsonify({"status": "success", "message": "Real-time monitoring stopped"})
    except Exception as e:
        logger.error(f"API error stopping monitoring: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/realtime/status', methods=['GET'])
def api_realtime_status():
    """API endpoint to get real-time monitoring status"""
    global COMPONENTS
    
    if not COMPONENTS['realtime_monitor']['instance']:
        return jsonify({
            "running": False,
            "message": "Real-time monitoring not initialized"
        })
    
    try:
        status_report = COMPONENTS['realtime_monitor']['instance'].get_status_report()
        return jsonify({
            "running": COMPONENTS['realtime_monitor']['instance'].is_running,
            "report": status_report
        })
    except Exception as e:
        logger.error(f"API error getting monitoring status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/realtime/threats', methods=['GET'])
def api_realtime_threats():
    """API endpoint to get detected threats in a clean, user-friendly format"""
    global COMPONENTS
    
    if 'realtime_monitor' in COMPONENTS and COMPONENTS['realtime_monitor']['instance']:
        try:
            status_report = COMPONENTS['realtime_monitor']['instance'].get_status_report()
            
            # Format threats for user-friendly display
            threats = []
            for file_path, details in status_report.get('suspicious_files', {}).items():
                threat = {
                    'file_name': os.path.basename(file_path),
                    'file_path': file_path,
                    'threat_type': details.get('detected_type', 'Unknown'),
                    'confidence': f"{details.get('confidence', 0)*100:.0f}%",
                    'detection_method': 'ML Model' if details.get('ml_detection') else 'Heuristic Analysis',
                    'file_hash': details.get('file_hash', 'N/A')[:16] + '...' if details.get('file_hash') else 'N/A',
                    'status': 'BLOCKED' if details.get('confidence', 0) > 0.8 else 'SUSPICIOUS',
                    'severity': 'HIGH' if details.get('confidence', 0) > 0.8 else 'MEDIUM',
                    'timestamp': datetime.now().isoformat()
                }
                threats.append(threat)
            
            # Sort by confidence (highest first)
            threats.sort(key=lambda x: float(x['confidence'].rstrip('%')), reverse=True)
            
            return jsonify({
                'status': 'success',
                'monitor_running': status_report.get('is_running', False),
                'total_threats': len(threats),
                'threats': threats,
                'monitored_directories': status_report.get('monitored_directories', []),
                'queue_size': status_report.get('queue_size', 0),
                'blacklisted_files': len(status_report.get('problematic_files', []))
            })
            
        except Exception as e:
            logger.error(f"Error getting realtime threats: {e}")
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Real-time monitor not available'}), 503

# Dashboard API routes
@app.route('/api/threat-overview')
def api_threat_overview():
    """API endpoint for threat overview"""
    if dashboard:
        return jsonify(dashboard.get_threat_overview())
    return jsonify({"error": "Dashboard not available"}), 503

@app.route('/api/geographic-distribution')
def api_geographic_distribution():
    """API endpoint for geographic distribution"""
    if dashboard:
        import plotly.utils
        geo_data = dashboard.get_geographic_distribution()
        return jsonify({
            'chart': json.dumps(geo_data, cls=plotly.utils.PlotlyJSONEncoder),
            'stats': geo_data.get('country_stats', {})
        })
    return jsonify({"error": "Dashboard not available"}), 503

@app.route('/api/malware-trends')
def api_malware_trends():
    """API endpoint for malware trends"""
    if dashboard:
        import plotly.utils
        trends = dashboard.get_malware_trends()
        return jsonify(json.dumps(trends, cls=plotly.utils.PlotlyJSONEncoder))
    return jsonify({"error": "Dashboard not available"}), 503

@app.route('/api/attack-vectors')
def api_attack_vectors():
    """API endpoint for attack vector analysis"""
    if dashboard:
        import plotly.utils
        vectors = dashboard.get_attack_vector_analysis()
        return jsonify({
            'frequency_chart': json.dumps(vectors['frequency_distribution'], cls=plotly.utils.PlotlyJSONEncoder),
            'success_chart': json.dumps(vectors['success_rates'], cls=plotly.utils.PlotlyJSONEncoder),
            'summary': vectors['summary']
        })
    return jsonify({"error": "Dashboard not available"}), 503

@app.route('/api/threat-timeline')
def api_threat_timeline():
    """API endpoint for threat timeline"""
    if dashboard:
        import plotly.utils
        timeline = dashboard.get_threat_timeline()
        return jsonify(json.dumps(timeline, cls=plotly.utils.PlotlyJSONEncoder))
    return jsonify({"error": "Dashboard not available"}), 503

@app.route('/api/sector-analysis')
def api_sector_analysis():
    """API endpoint for sector analysis"""
    if dashboard:
        import plotly.utils
        analysis = dashboard.get_sector_analysis()
        return jsonify(json.dumps(analysis, cls=plotly.utils.PlotlyJSONEncoder))
    return jsonify({"error": "Dashboard not available"}), 503

@app.route('/api/generate-report/<timeframe>')
def api_generate_report(timeframe):
    """API endpoint for generating threat reports"""
    if dashboard:
        report = dashboard.generate_threat_report(timeframe)
        return jsonify(report)
    return jsonify({"error": "Dashboard not available"}), 503

# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('error.html', error="File too large"), 413

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', error="Server error"), 500

# Route to display component status
@app.route('/status')
def component_status():
    return render_template('status.html', components=COMPONENTS)

# Fallback method to extract features when feature extractor fails
def fallback_extract_features(file_path):
    """
    A simple fallback feature extractor when the main one fails
    """
    logger.warning(f"Using fallback feature extraction for {file_path}")
    import os
    import hashlib
    import magic
    import numpy as np
    
    features = {}
    
    # File metadata
    try:
        file_size = os.path.getsize(file_path)
        features['file_size'] = file_size
    except:
        features['file_size'] = 0
    
    # File type
    try:
        file_type = magic.from_file(file_path)
        features['is_executable'] = 1 if 'executable' in file_type.lower() else 0
        features['is_dll'] = 1 if '.dll' in file_path.lower() or 'dll' in file_type.lower() else 0
    except:
        features['is_executable'] = 1 if file_path.endswith('.exe') else 0
        features['is_dll'] = 1 if file_path.endswith('.dll') else 0
    
    # Entropy calculation
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if data:
            entropy = 0
            for x in range(256):
                p_x = data.count(bytes([x])) / len(data)
                if p_x > 0:
                    entropy += -p_x * np.log2(p_x)
            features['entropy'] = entropy
        else:
            features['entropy'] = 0
    except:
        features['entropy'] = 0
    
    # File hash
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        features['md5_hash'] = int(md5[:8], 16) / (1 << 32)  # Normalize to [0, 1]
    except:
        features['md5_hash'] = 0
    
    # Convert to 2D array for sklearn compatibility
    return np.array([[
        features['file_size'], 
        features['is_executable'],
        features['is_dll'],
        features['entropy'],
        features['md5_hash']
    ]])

# Simplified fallback malware detector
def fallback_detect_malware(file_path):
    """
    A simple fallback method when ML model fails
    """
    logger.warning(f"Using fallback malware detection for {file_path}")
    import re
    import os
    
    # Read file content
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
    except:
        return True  # Consider suspicious if we can't read it
    
    # Suspicious patterns
    patterns = [
        rb'CreateRemoteThread',
        rb'VirtualAllocEx', 
        rb'WriteProcessMemory',
        rb'NtUnmapViewOfSection',
        rb'ShellExecute',
        rb'GetProcAddress',
        rb'LoadLibrary',
        rb'CreateProcess',
        rb'CreateFile',
        rb'WriteFile',
        rb'RegSetValue',
        rb'WinExec',
        rb'URLDownloadToFile',
        rb'GetTempPath',
        rb'SetWindowsHookEx',
        rb'WSASocket',
        rb'connect',
        rb'HTTP',
        rb'HTTPS',
        rb'WScript.Shell',
        rb'powershell',
        rb'cmd.exe',
        rb'rundll32',
        rb'encrypt',
        rb'ransom',
        rb'bitcoin',
        rb'password',
        rb'malware',
        rb'trojan',
        rb'virus',
        rb'threat',
        rb'exploit',
        rb'attack',
        rb'hack',
    ]
    
    # Check for suspicious patterns
    suspicious_matches = 0
    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            suspicious_matches += 1
    
    # File entropy
    entropy = 0
    if content:
        byte_counters = {}
        file_size = len(content)
        for byte in content:
            if byte not in byte_counters:
                byte_counters[byte] = 0
            byte_counters[byte] += 1
        
        import math
        for count in byte_counters.values():
            probability = count / file_size
            entropy -= probability * math.log2(probability)
    
    # File size (large files or very small files can be suspicious)
    file_size = os.path.getsize(file_path)
    
    # Decision factors
    high_entropy = entropy > 7.0  # Very high entropy often indicates encryption or packing
    strange_size = file_size < 1000 or file_size > 20000000  # Unusually small or large
    many_patterns = suspicious_matches > 5  # Multiple suspicious API calls
    
    # Final decision
    is_suspicious = high_entropy and (strange_size or many_patterns)
    
    logger.debug(f"Fallback detection: entropy={entropy}, patterns={suspicious_matches}, "
                f"size={file_size}, suspicious={is_suspicious}")
    
    return is_suspicious

# Add route for model explanation visualization
@app.route('/explain/<file_id>')
def explain_result(file_id):
    """
    Display model explanation for a specific result
    
    Args:
        file_id: ID of the analyzed file
    
    Returns:
        Rendered explanation template
    """
    try:
        # Get the analysis results for the file
        result_file = os.path.join(app.config['UPLOAD_FOLDER'], 'results', f"{file_id}.json")
        if not os.path.exists(result_file):
            flash('Analysis result not found', 'danger')
            return redirect(url_for('index'))
            
        with open(result_file, 'r') as f:
            result = json.load(f)
            
        # Get the feature vector from the result
        if 'features' not in result:
            flash('Feature data not available for explanation', 'warning')
            return redirect(url_for('result', file_id=file_id))
            
        feature_vector = result['features']
        feature_names = result.get('feature_names', [f"Feature_{i}" for i in range(len(feature_vector))])
        
        # Load the model explainer
        from model_explainer import ModelExplainer
        explainer = ModelExplainer(app.config['MODEL_PATH'])
        
        # Generate the explanation
        explanation = explainer.explain_prediction(feature_vector, feature_names)
        
        # Generate the visualization
        explanation_image = os.path.join(app.config['UPLOAD_FOLDER'], 'explanations', f"{file_id}.png")
        os.makedirs(os.path.dirname(explanation_image), exist_ok=True)
        explainer.generate_explanation_plot(explanation, explanation_image)
        
        # Prepare data for the template
        explanation_data = {
            'top_features': explanation['top_features'],
            'prediction': explanation['prediction'],
            'confidence': explanation['confidence'],
            'image_path': f"/uploads/explanations/{file_id}.png"
        }
        
        return render_template('explanation.html', 
                               file_id=file_id, 
                               result=result, 
                               explanation=explanation_data)
                               
    except Exception as e:
        logger.error(f"Error generating explanation: {e}")
        flash(f"Error generating explanation: {str(e)}", 'danger')
        return redirect(url_for('result', file_id=file_id))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run the Malware Detection System')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('--host', default='0.0.0.0', help='Host to run the server on')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    args = parser.parse_args()
    
    if args.debug:
        app.run(debug=True, host=args.host, port=args.port)
    else:
        # In production, use Waitress WSGI server
        from waitress import serve
        print(f"Starting production server on {args.host}:{args.port}")
        serve(app, host=args.host, port=args.port, threads=10)

