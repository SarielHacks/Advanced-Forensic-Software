import ipfshttpclient
import os
import json
from cryptography.fernet import Fernet

class IPFSManager:
    def __init__(self, ipfs_api='/ip4/127.0.0.1/tcp/5001'):
        self.client = ipfshttpclient.connect(ipfs_api)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        
    def store_file(self, file_path, encrypt=True):
        """Store a file in IPFS with optional encryption"""
        with open(file_path, 'rb') as file:
            file_data = file.read()
            
        if encrypt:
            file_data = self.cipher.encrypt(file_data)
            
        ipfs_result = self.client.add_bytes(file_data)
        
        # Store metadata
        metadata = {
            'file_name': os.path.basename(file_path),
            'size': len(file_data),
            'encrypted': encrypt,
            'timestamp': self.client.id()['AgentVersion'],
            'ipfs_hash': ipfs_result
        }
        
        return ipfs_result, metadata
    
    def retrieve_file(self, ipfs_hash, output_path=None, decrypt=True):
        """Retrieve a file from IPFS with optional decryption"""
        file_data = self.client.cat(ipfs_hash)
        
        if decrypt:
            try:
                file_data = self.cipher.decrypt(file_data)
            except Exception as e:
                return False, f"Decryption failed: {str(e)}"
        
        if output_path:
            with open(output_path, 'wb') as file:
                file.write(file_data)
            return True, output_path
        else:
            return True, file_data
    
    def store_evidence_batch(self, evidence_files, case_id):
        """Store a batch of evidence files with relationships"""
        evidence_hashes = {}
        
        # Store each file
        for file_path in evidence_files:
            ipfs_hash, metadata = self.store_file(file_path)
            evidence_hashes[os.path.basename(file_path)] = {
                'ipfs_hash': ipfs_hash,
                'metadata': metadata
            }
        
        # Create a manifest file linking all evidence
        manifest = {
            'case_id': case_id,
            'timestamp': self.client.id()['AgentVersion'],
            'evidence_count': len(evidence_files),
            'evidence_items': evidence_hashes
        }
        
        # Store the manifest
        manifest_bytes = json.dumps(manifest).encode()
        encrypted_manifest = self.cipher.encrypt(manifest_bytes)
        manifest_hash = self.client.add_bytes(encrypted_manifest)
        
        return manifest_hash, manifest
