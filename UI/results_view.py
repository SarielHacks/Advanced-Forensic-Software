from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QTextEdit, 
                            QPushButton, QHBoxLayout, QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt
from UI.ui_components import UIComponents
from datetime import datetime
import os
import webbrowser

class ResultsView(QWidget):
    def __init__(self, report_generator, investigator_info):
        super().__init__()
        self.report_generator = report_generator
        self.investigator_info = investigator_info
        self.current_evidence = None
        self.current_analysis = None
        self.current_blockchain = None
        self.case_start_time = datetime.now()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        
        # Title with case info
        title = f"🔍 Forensic Analysis Results | Case {self.report_generator.case_id}"
        layout.addWidget(UIComponents.create_label(title, 18))
        
        # Investigator info
        investigator_text = (f"Investigator: {self.investigator_info['name']} | "
                            f"Badge: {self.investigator_info['badge_id']} | "
                            f"Started: {self.case_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        layout.addWidget(UIComponents.create_label(investigator_text, 10))
        
        # Results Summary
        self.summary_label = UIComponents.create_label("Initializing forensic analysis...", style="border: 1px solid #ccc; padding: 5px;")
        layout.addWidget(self.summary_label)
        
        # Analysis Views
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("font-family: monospace;")
        
        self.blockchain_text = QTextEdit()
        self.blockchain_text.setReadOnly(True)
        
        self.timeline_text = QTextEdit()
        self.timeline_text.setReadOnly(True)
        
        layout.addWidget(UIComponents.create_label("Forensic Timeline:"))
        layout.addWidget(self.timeline_text)
        layout.addWidget(UIComponents.create_label("Analysis Details:"))
        layout.addWidget(self.details_text)
        layout.addWidget(UIComponents.create_label("Blockchain Verification:"))
        layout.addWidget(self.blockchain_text)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        
        self.html_report_btn = QPushButton("🌐 Generate HTML Report")
        self.html_report_btn.clicked.connect(lambda: self.generate_report("html"))
        self.html_report_btn.setEnabled(False)
        btn_layout.addWidget(self.html_report_btn)
        
        self.pdf_report_btn = QPushButton("📄 Generate PDF Report")
        self.pdf_report_btn.clicked.connect(lambda: self.generate_report("pdf"))
        self.pdf_report_btn.setEnabled(False)
        btn_layout.addWidget(self.pdf_report_btn)
        
        self.verify_btn = QPushButton("🔗 Verify Chain of Evidence")
        self.verify_btn.clicked.connect(self.verify_evidence_chain)
        self.verify_btn.setEnabled(False)
        btn_layout.addWidget(self.verify_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def update_results(self, evidence_data, analysis_results, blockchain_info):
        """Update the view with complete analysis results"""
        self.current_evidence = evidence_data
        self.current_analysis = analysis_results
        self.current_blockchain = blockchain_info
        
        # Update summary
        self.summary_label.setText(
            f"✔️ Disk Image Verified: {evidence_data.get('disk_hash_short', 'N/A')} | "
            f"📂 Files Analyzed: {analysis_results.get('file_count', 0)} | "
            f"⚠️ Suspicious Items: {len(analysis_results.get('suspicious_items', []))} | "
            f"⏱️ Duration: {analysis_results.get('duration', 0):.1f}s"
        )
        
        # Update timeline
        self.timeline_text.setPlainText(
            "\n".join(
                f"{step['timestamp']} - {step['name']} ({step['duration']:.1f}s)"
                for step in analysis_results.get('timeline', [])
            )
        )
        
        # Update analysis details
        analysis_text = [
            "=== EVIDENCE DETAILS ===",
            f"File Path: {evidence_data.get('file_path', 'N/A')}",
            f"Original Hash: {evidence_data.get('original_hash', 'N/A')}",
            f"Disk Image Hash: {evidence_data.get('disk_hash', 'N/A')}",
            f"Acquisition Time: {evidence_data.get('acquisition_time', 'N/A')}",
            "",
            "=== SUSPICIOUS CONTENT ==="
        ]
        
        for item in analysis_results.get('suspicious_items', []):
            analysis_text.extend([
                f"\n■ File: {item['file']}",
                f"  Confidence: {float(item['confidence'])*100:.1f}%",
                f"  Content: {item['text']}",
                f"  Context: {item.get('context', 'N/A')}"
            ])
        
        self.details_text.setPlainText("\n".join(analysis_text))
        
        # Update blockchain info
        self.blockchain_text.setPlainText(
            "\n".join([
                "=== BLOCKCHAIN VERIFICATION ===",
                f"Transaction ID: {blockchain_info.get('tx_id', 'Pending')}",
                f"Block Number: {blockchain_info.get('block_number', 'Pending')}",
                f"IPFS Hash: {blockchain_info.get('ipfs_hash', 'Pending')}",
                f"Verification: {blockchain_info.get('verification_status', 'Pending')}",
                f"Timestamp: {blockchain_info.get('timestamp', 'Pending')}"
            ])
        )
        
        # Enable buttons
        self.html_report_btn.setEnabled(True)
        self.pdf_report_btn.setEnabled(True)
        self.verify_btn.setEnabled(True)

    def generate_report(self, format):
        """Generate and handle HTML/PDF reports"""
        if not all([self.current_evidence, self.current_analysis, self.current_blockchain]):
            QMessageBox.warning(self, "Error", "Incomplete analysis data")
            return
            
        if not hasattr(self.report_generator, 'config') or not self.report_generator.config:
            raise ValueError("Report generator configuration missing")
            
        if 'ai_analysis' not in self.report_generator.config.get('ai_ml', {}):
            raise ValueError("Missing AI analysis configuration section")
            
        try:
            # Generate report
            report_content, fmt = self.report_generator.generate_report(
                evidence_data=self.current_evidence,
                analysis_results=self.current_analysis,
                blockchain_info=self.current_blockchain,
                user_info=self.investigator_info,
                format=format
            )

            # Save report
            saved_path = self.report_generator.save_report(
                report_content,
                fmt,
                self
            )

            if saved_path:
                # Open the report
                if format == "html":
                    webbrowser.open(f"file://{os.path.abspath(saved_path)}")
                else:
                    self._open_pdf(saved_path)

                QMessageBox.information(
                    self,
                    "Report Generated",
                    f"{fmt.upper()} report saved to:\n{saved_path}"
                )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Report Generation Failed",
                f"Error: {str(e)}"
            )

    def _open_pdf(self, filepath):
        """Open PDF in default viewer"""
        try:
            if os.name == 'nt':  # Windows
                os.startfile(filepath)
            elif os.name == 'posix':  # macOS/Linux
                if os.uname().sysname == 'Darwin':
                    os.system(f'open "{filepath}"')
                else:
                    os.system(f'xdg-open "{filepath}"')
        except Exception as e:
            QMessageBox.warning(
                self,
                "PDF Viewer Error",
                f"Could not open PDF:\n{str(e)}"
            )

    def verify_evidence_chain(self):
        """Verify the complete chain of evidence"""
        verification = self.report_generator.verify_complete_chain(
            self.current_evidence,
            self.current_blockchain
        )
        
        msg = QMessageBox()
        msg.setWindowTitle("Chain of Evidence Verification")
        msg.setText(verification['message'])
        msg.setDetailedText("\n".join(verification.get('details', [])))
        msg.setIcon(QMessageBox.Icon.Information if verification['valid'] else QMessageBox.Icon.Warning)
        msg.exec()
