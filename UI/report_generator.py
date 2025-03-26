import os

def generate_report(evidence_path):
    """
    Generates a simple forensic analysis report based on the provided evidence path.
    The report is saved as a text file.
    """
    if not evidence_path:
        return "Error: No evidence provided."

    report_content = f"""
    Cyber Forensic Analysis Report
    -----------------------------------
    Evidence Path: {evidence_path}
    Status: Successfully Analyzed
    Observations: No anomalies detected (sample analysis).
    
    This is an auto-generated forensic report.
    """

    # Save report
    report_filename = "forensic_report.txt"
    with open(report_filename, "w", encoding="utf-8") as report_file:
        report_file.write(report_content)

    return f"Report generated: {report_filename}"
