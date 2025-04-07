import hashlib
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

class EvidenceValidator:
    def __init__(self, hyperledger_manager):
        self.hyperledger_manager = hyperledger_manager
        self._generate_key_pair()
        
    def _generate_key_pair(self):
        """Generate public/private key pair for signing"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def calculate_multi_hash(self, data):
        """Calculate multiple hash algorithms for the same data"""
        if isinstance(data, str):
            data = data.encode()
            
        hashes = {
            'sha256': hashlib.sha256(data).hexdigest(),
            'sha3_256': hashlib.sha3_256(data).hexdigest(),
            'blake2b': hashlib.blake2b(data).hexdigest()
        }
        return hashes
    
    def sign_evidence(self, evidence_data):
        """Create digital signature for evidence"""
        if isinstance(evidence_data, dict):
            evidence_data = json.dumps(evidence_data).encode()
        elif isinstance(evidence_data, str):
            evidence_data = evidence_data.encode()
            
        signature = self.private_key.sign(
            evidence_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()
    
    def verify_signature(self, evidence_data, signature, public_key=None):
        """Verify digital signature of evidence"""
        if isinstance(evidence_data, dict):
            evidence_data = json.dumps(evidence_data).encode()
        elif isinstance(evidence_data, str):
            evidence_data = evidence_data.encode()
            
        signature = bytes.fromhex(signature)
        
        if public_key is None:
            public_key = self.public_key
            
        try:
            public_key.verify(
                signature,
                evidence_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def validate_blockchain_record(self, evidence_id, current_hash):
        """Validate evidence against blockchain record"""
        blockchain_record = self.hyperledger_manager.get_evidence_history(evidence_id)
        if not blockchain_record:
            return False, "No blockchain record found"
            
        # Compare current hash with latest hash in blockchain
        latest_record = blockchain_record[-1]
        if latest_record['hash_value'] != current_hash:
            return False, "Hash mismatch - evidence may be tampered"
            
        return True, "Evidence validated successfully"
