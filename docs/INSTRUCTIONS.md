Installation Guide
This document provides step-by-step instructions to install and set up the Digital Forensics Framework on your system.

Prerequisites
Before installing, ensure you have the following dependencies installed:

- Operating System: Windows, Linux (recommended: Ubuntu), or macOS
- Python: Version 3.8+
- Git: Installed for cloning the repository
- Pip: Ensure pip is up-to-date
- Hyperledger Fabric SDK: Required for blockchain integration
- IPFS (InterPlanetary File System): Needed for distributed storage

Step 1: Clone the Repository
Open a terminal or command prompt and run:
git clone https://github.com/your-repo/digital-forensics-framework.git
cd digital-forensics-framework

Step 2: Set Up a Virtual Environment (Optional but Recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

Step 3: Install Dependencies
Run the following command to install required packages:
pip install -r requirements.txt

Step 4: Configure Blockchain and Storage
Hyperledger Fabric Setup

Follow Hyperledger Fabric’s installation guide
Update config/blockchain_config.json with the network details
IPFS Setup

Download and install IPFS from here
Initialize IPFS:
ipfs init
ipfs daemon
Configure storage settings in config/settings.json

Step 5: Running the Framework
Forensic Analysis (Command Line Mode)
To analyze a forensic image, run:
python src/core_forensics/disk_acquisition_manager.py --disk /dev/sdb

Launching the UI
Run the UI-based application:
python src/ui/main_window.py

Step 6: Running Tests
To verify installation and functionality, run:
pytest tests/

Uninstallation
To remove the framework, simply delete the project directory and uninstall dependencies:
rm -rf digital-forensics-framework
pip uninstall -r requirements.txt

Troubleshooting
If you encounter issues:
- Ensure Python 3.8+ is installed correctly
- Run pip install --upgrade pip before installing dependencies
- Verify IPFS and Hyperledger Fabric are correctly installed
- For additional support, check our GitHub Issues.
