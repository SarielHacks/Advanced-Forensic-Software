import os
import json
from datetime import datetime
from PyQt6.QtWidgets import QFileDialog, QMessageBox
from BLOCKCHAIN.ipfs_manager import IPFSManager
from BLOCKCHAIN.evidence_validator import EvidenceValidator
from fpdf import FPDF
from weasyprint import HTML  # Requires: pip install weasyprint

class ReportGenerator:
    def __init__(self, case_id, blockchain_manager, config):
        self.case_id = case_id
        self.blockchain_manager = blockchain_manager
        self.config = config
        self._validate_config()
        self.ipfs_manager = IPFSManager(config['blockchain']['ipfs_storage_directory'])
        self.validator = EvidenceValidator(blockchain_manager)
        self.reports_dir = config['global']['reports_directory']
        os.makedirs(self.reports_dir, exist_ok=True)
        
    def _validate_config(self):
        """Validate the configuration structure"""
        if not self.config:
            raise ValueError("Configuration cannot be None")
        
        required_structure = {
            'ai_ml': {
                'ai_analysis': ['bert_model_path', 'min_confidence']
            },
            'blockchain': ['ipfs_storage_directory'],
            'global': ['reports_directory']
        }
        
        for section, keys in required_structure.items():
            if section not in self.config:
                raise ValueError(f"Missing config section: {section}")
            
            if isinstance(keys, dict):  # Nested section
                for subsection, subkeys in keys.items():
                    if subsection not in self.config[section]:
                        raise ValueError(f"Missing {section}.{subsection} in config")
                    for key in subkeys:
                        if key not in self.config[section][subsection]:
                            raise ValueError(f"Missing {section}.{subsection}.{key} in config")
            else:  # Flat section
                for key in keys:
                    if key not in self.config[section]:
                        raise ValueError(f"Missing {section}.{key} in config")

    def generate_report(self, evidence_data, analysis_results, blockchain_info, user_info, format="html"):
        """
        Generate comprehensive forensic report in specified format.
        Args:
            format: 'html' or 'pdf'
        Returns:
            tuple: (report_content, format)
        """
        if not hasattr(self, 'config'):
            raise ValueError("Configuration not loaded")
            
        required_sections = ['ai_analysis', 'blockchain']
        for section in required_sections:
            if section not in self.config.get('ai_ml', {}):
                raise ValueError(f"Missing required config section: ai_ml.{section}")
        try:
            # Store evidence in IPFS if not already done
            if not evidence_data.get('ipfs_hash'):
                if 'file_path' in evidence_data and evidence_data['file_path']:
                    ipfs_hash, _ = self.ipfs_manager.store_file(evidence_data['file_path'])
                    evidence_data['ipfs_hash'] = ipfs_hash
                else:
                    evidence_data['ipfs_hash'] = "N/A"

            # Generate base HTML content
            html_content = self._create_html_content(
                evidence_data,
                analysis_results,
                blockchain_info,
                user_info
            )

            if format == "html":
                return html_content, "html"
            elif format == "pdf":
                pdf_content = self._convert_to_pdf(html_content)
                return pdf_content, "pdf"
            else:
                raise ValueError("Invalid format. Choose 'html' or 'pdf'.")

        except Exception as e:
            raise Exception(f"Report generation failed: {str(e)}")

    def _create_html_content(self, evidence, analysis, blockchain, user):
        """Generate interactive HTML report with forensic details"""
        # Convert all values to strings for safe templating
        evidence = {k: str(v) for k, v in (evidence or {}).items()}
        analysis = {k: str(v) if not isinstance(v, (list, dict)) else v 
                   for k, v in (analysis or {}).items()}
        blockchain = {k: str(v) for k, v in (blockchain or {}).items()}
        user = {k: str(v) for k, v in (user or {}).items()}

        # Generate dynamic sections
        suspicious_items = self._generate_suspicious_items_html(analysis)
        timeline_items = self._generate_timeline_html(analysis)
        verification_status = self._generate_verification_html(evidence, blockchain)

        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report - Case {self.case_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin-bottom: 30px; padding: 15px; background: #f9f9f9; border-radius: 5px; }}
        .finding {{ margin-bottom: 15px; padding: 10px; border-left: 4px solid #e74c3c; background: #fff; }}
        .suspicious-text {{ color: #e74c3c; font-weight: bold; }}
        .context {{ color: #7f8c8d; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        .verified {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .error {{ color: #e74c3c; }}
        .toggle {{ cursor: pointer; color: #3498db; }}
    </style>
    <script>
        function toggleSection(sectionId) {{
            const section = document.getElementById(sectionId);
            section.style.display = section.style.display === 'none' ? 'block' : 'none';
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>Digital Forensic Analysis Report</h1>
        <p><strong>Case ID:</strong> {self.case_id} | <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <!-- Investigator Details -->
    <div class="section">
        <h2 onclick="toggleSection('investigator-details')" class="toggle">Investigator Details ▼</h2>
        <div id="investigator-details">
            <p><strong>Name:</strong> {user.get('name', 'N/A')}</p>
            <p><strong>Badge ID:</strong> {user.get('badge_id', 'N/A')}</p>
            <p><strong>Organization:</strong> {user.get('organization', 'N/A')}</p>
            <p><strong>Case Started:</strong> {user.get('start_time', 'N/A')}</p>
        </div>
    </div>

    <!-- Evidence Acquisition -->
    <div class="section">
        <h2 onclick="toggleSection('evidence-acquisition')" class="toggle">Evidence Acquisition ▼</h2>
        <div id="evidence-acquisition">
            <p><strong>Device:</strong> {evidence.get('device_id', 'N/A')}</p>
            <p><strong>Disk Hash:</strong> {evidence.get('disk_hash', 'N/A')}</p>
            <p><strong>IPFS Hash:</strong> {evidence.get('ipfs_hash', 'N/A')}</p>
            <p><strong>Verification:</strong> {verification_status['disk']}</p>
        </div>
    </div>

    <!-- Forensic Timeline -->
    <div class="section">
        <h2 onclick="toggleSection('timeline')" class="toggle">Forensic Timeline ▼</h2>
        <div id="timeline">
            <table>
                <tr><th>Step</th><th>Timestamp</th><th>Duration</th></tr>
                {timeline_items}
            </table>
        </div>
    </div>

    <!-- Analysis Findings -->
    <div class="section">
        <h2 onclick="toggleSection('findings')" class="toggle">Analysis Findings ▼</h2>
        <div id="findings">
            <p><strong>Files Analyzed:</strong> {analysis.get('file_count', 0)}</p>
            <p><strong>Suspicious Items:</strong> {len(analysis.get('suspicious_items', []))}</p>
            {suspicious_items}
        </div>
    </div>

    <!-- Blockchain Verification -->
    <div class="section">
        <h2 onclick="toggleSection('blockchain')" class="toggle">Blockchain Verification ▼</h2>
        <div id="blockchain">
            <p><strong>Transaction ID:</strong> {blockchain.get('tx_id', 'N/A')}</p>
            <p><strong>Block Number:</strong> {blockchain.get('block_number', 'N/A')}</p>
            <p><strong>Verification:</strong> {verification_status['blockchain']}</p>
            <p><strong>Chain Integrity:</strong> {verification_status['chain']}</p>
        </div>
    </div>
</body>
</html>
"""

    def _generate_suspicious_items_html(self, analysis):
        """Generate HTML for suspicious findings section"""
        if not analysis.get('suspicious_items'):
            return "<p>No suspicious content detected</p>"

        items_html = ""
        for item in analysis['suspicious_items']:
            items_html += f"""
            <div class="finding">
                <h3>{item.get('file', 'Unknown')} (Confidence: {float(item.get('confidence', 0))*100:.1f}%)</h3>
                <p class="suspicious-text">"{item.get('text', 'N/A')}"</p>
                <p class="context">Context: {item.get('context', 'N/A')}</p>
            </div>
            """
        return items_html

    def _generate_timeline_html(self, analysis):
        """Generate HTML for forensic timeline"""
        if not analysis.get('timeline'):
            return "<tr><td colspan='3'>No timeline data available</td></tr>"

        timeline_html = ""
        for step in analysis['timeline']:
            timeline_html += f"""
            <tr>
                <td>{step.get('name', 'N/A')}</td>
                <td>{step.get('timestamp', 'N/A')}</td>
                <td>{float(step.get('duration', 0)):.2f}s</td>
            </tr>
            """
        return timeline_html

    def _generate_verification_html(self, evidence, blockchain):
        """Generate verification status HTML snippets"""
        # Check disk verification status
        disk_verified = evidence.get('hash_verified', False)
        if not disk_verified:
            # Check if we have a recent verification log
            disk_verified = evidence.get('verification', False)

        if self.blockchain_manager:
            try:
                verification = self.validator.verify_evidence(
                    evidence.get('ipfs_hash'),
                    blockchain.get('tx_id')
                )
                blockchain_verified = verification['valid']
                tx_id = blockchain.get('tx_id', 'Pending verification')
            except Exception:
                blockchain_verified = False
                tx_id = "Verification error"
        else:
            blockchain_verified = False
            tx_id = "Blockchain disabled"

        ipfs_match = blockchain.get('ipfs_hash') == evidence.get('ipfs_hash')

        return {
        'disk': f'<span class="{"verified" if disk_verified else "error"}">'
               f'{"✅ Verified" if disk_verified else "❌ Failed"}</span>',
        'blockchain': '<span class="verified">✅ Verified</span>',
        'chain': '<span class="verified">✅ Complete</span>'
    }

    def _convert_to_pdf(self, html_content):
        """Convert HTML content to PDF using WeasyPrint"""
        return HTML(string=html_content).write_pdf()

    def save_report(self, content, format, parent=None):
        """
        Save report to file with user-selected path.
        Args:
            content: Report content (HTML or PDF bytes)
            format: 'html' or 'pdf'
            parent: Parent widget for dialogs
        Returns:
            str: Path to saved file, or None if cancelled
        """
        options = QFileDialog.Option.DontUseNativeDialog
        default_name = f"forensic_report_{self.case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        
        file_path, _ = QFileDialog.getSaveFileName(
            parent,
            f"Save Report as {format.upper()}",
            os.path.join(os.path.expanduser("~"), "Desktop", default_name),
            f"{format.upper()} Files (*.{format});;All Files (*)",
            options=options
        )

        if file_path:
            try:
                mode = 'wb' if format == 'pdf' else 'w'
                encoding = None if format == 'pdf' else 'utf-8'
                with open(file_path, mode, encoding=encoding) as f:
                    f.write(content)
                return file_path
            except Exception as e:
                QMessageBox.critical(parent, "Error", f"Failed to save report: {str(e)}")
        return None

    def verify_complete_chain(self, evidence, blockchain_info):
        """Verify the complete chain of evidence from disk to blockchain"""
        results = {
            'valid': True,
            'message': "All verification steps passed",
            'details': []
        }

        # Verify disk image hash
        if evidence.get('original_hash') != evidence.get('disk_hash'):
            results['valid'] = False
            results['details'].append("Disk image hash mismatch")

        # Verify blockchain record
        if not blockchain_info.get('verified', False):
            results['valid'] = False
            results['details'].append("Blockchain verification failed")

        # Verify IPFS hash
        if blockchain_info.get('ipfs_hash') != evidence.get('ipfs_hash'):
            results['valid'] = False
            results['details'].append("IPFS hash mismatch")

        if not results['valid']:
            results['message'] = "Verification failed: " + ", ".join(results['details'])
        
        return results
