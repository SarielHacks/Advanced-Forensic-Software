import asyncio
import os
import json
import logging
from hfc.fabric import Client
from hfc.util.crypto.crypto import ecies

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class HyperledgerManager:
    def __init__(self, config_path='/home/sariel/Desktop/Automated_Forensics_Software/BLOCKCHAIN/network-config.json'):
        try:
            # Create new event loop if in non-main thread
            try:
                self.loop = asyncio.get_event_loop()
            except RuntimeError:
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)
            
            self.client = Client(net_profile=config_path)
            self.channel_name = os.getenv('CHANNEL_NAME', 'forensicchannel')
            self.cc_name = os.getenv('CHAINCODE_NAME', 'forensic_chaincode')
            self.initialize_client()
        except Exception as e:
            logging.error(f"Error initializing Hyperledger client: {e}")
            raise

    def initialize_client(self):
        """Initialize the Fabric client with crypto materials."""
        try:
            admin = self.client.get_user(os.getenv('ORG_NAME', 'org1.example.com'), 'Admin')
            self.client.new_channel(self.channel_name)
            logging.info("Hyperledger client initialized successfully.")
        except Exception as e:
            logging.error(f"Error during client initialization: {e}")
            raise

    def register_evidence(self, evidence_id, metadata, hash_value):
        """Register new evidence on the blockchain."""
        try:
            args = [evidence_id, json.dumps(metadata), hash_value]
            response = self.client.chaincode_invoke(
                requestor=self.client.get_user(os.getenv('ORG_NAME', 'org1.example.com'), 'User1'),
                channel_name=self.channel_name,
                peers=[os.getenv('PEER_NAME', 'peer0.org1.example.com')],  # Use 'peers' instead of 'peer_names'
                cc_name=self.cc_name,
                fcn='registerEvidence',
                args=args,
                cc_pattern=None
            )
            logging.info(f"Evidence registered: {response}")
            return response
        except Exception as e:
            logging.error(f"Error registering evidence: {e}")
            return None

    def get_evidence_history(self, evidence_id):
        """Retrieve the chain of custody for a piece of evidence."""
        try:
            args = [evidence_id]
            response = self.client.chaincode_query(
                requestor=self.client.get_user(os.getenv('ORG_NAME', 'org1.example.com'), 'User1'),
                channel_name=self.channel_name,
                peers=[os.getenv('PEER_NAME', 'peer0.org1.example.com')],
                cc_name=self.cc_name,
                fcn='getEvidenceHistory',
                args=args,
                cc_pattern=None
            )
            if response:
                return json.loads(response)
            else:
                logging.warning(f"No evidence history found for ID: {evidence_id}")
                return None
        except Exception as e:
            logging.error(f"Error retrieving evidence history: {e}")
            return None

    def create_transaction(self, evidence_id, action, user_id, timestamp):
        """Record a transaction for evidence handling."""
        try:
            args = [evidence_id, action, user_id, timestamp]
            response = self.client.chaincode_invoke(
                requestor=self.client.get_user(os.getenv('ORG_NAME', 'org1.example.com'), 'User1'),
                channel_name=self.channel_name,
                peers=[os.getenv('PEER_NAME', 'peer0.org1.example.com')],  # Use 'peers' instead of 'peer_names'
                cc_name=self.cc_name,
                fcn='recordTransaction',
                args=args,
                cc_pattern=None
            )
            logging.info(f"Transaction recorded for evidence {evidence_id}: {response}")
            return response
        except Exception as e:
            logging.error(f"Error creating transaction: {e}")
            return None

    def check_connection(self):
        """Check if the Hyperledger Fabric client is connected and operational."""
        try:
            peers = self.client.get_net_info()['peers']
            if peers:
                logging.info("Connected to Fabric network successfully.")
                return True
            else:
                logging.warning("No peers found in the network.")
                return False
        except Exception as e:
            logging.error(f"Error checking network connection: {e}")
            return False
