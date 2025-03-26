import os
import hashlib
import logging
import datetime
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

@dataclass
class DiskMetadata:
    """Stores metadata information about a disk."""
    serial_number: str
    model: str
    size_bytes: int
    sector_size: int
    creation_date: datetime.datetime
    hash_value: str

class WriteBlocker:
    """Implements write blocking functionality to prevent disk modification."""
    
    def __init__(self):
        self._blocked_devices = set()
        logging.info("Write blocker initialized")
    
    def block_device(self, device_path: str) -> bool:
        """
        Enable write blocking for a specific device.
        
        Args:
            device_path: Path to the device to block
            
        Returns:
            bool: True if successfully blocked, False otherwise
        """
        try:
            # Simulate hardware write blocking by marking device as read-only
            os.system(f"blockdev --setro {device_path}")
            self._blocked_devices.add(device_path)
            logging.info(f"Write blocking enabled for device: {device_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to enable write blocking: {str(e)}")
            return False
    
    def unblock_device(self, device_path: str) -> bool:
        """
        Disable write blocking for a specific device.
        
        Args:
            device_path: Path to the device to unblock
            
        Returns:
            bool: True if successfully unblocked, False otherwise
        """
        try:
            if device_path in self._blocked_devices:
                os.system(f"blockdev --setrw {device_path}")
                self._blocked_devices.remove(device_path)
                logging.info(f"Write blocking disabled for device: {device_path}")
                return True
            return False
        except Exception as e:
            logging.error(f"Failed to disable write blocking: {str(e)}")
            return False

class DiskImager:
    """Handles creation and verification of disk images."""
    
    def __init__(self, output_directory: str):
        self.output_directory = output_directory
        os.makedirs(output_directory, exist_ok=True)
        logging.info(f"Disk imager initialized with output directory: {output_directory}")
    
    def create_image(self, source_device: str, image_name: str) -> Tuple[bool, str]:
        """
        Create a forensic image of a disk.
        
        Args:
            source_device: Path to the source device
            image_name: Name for the output image file
            
        Returns:
            Tuple[bool, str]: Success status and path to created image
        """
        try:
            image_path = os.path.join(self.output_directory, f"{image_name}.dd")
            
            # Create raw disk image using dd
            os.system(f"dd if={source_device} of={image_path} bs=4M status=progress")
            
            # Calculate hash of the created image
            image_hash = self._calculate_hash(image_path)
            
            # Save hash to accompanying file
            hash_path = f"{image_path}.hash"
            with open(hash_path, 'w') as f:
                f.write(image_hash)
            
            logging.info(f"Disk image created successfully: {image_path}")
            return True, image_path
            
        except Exception as e:
            logging.error(f"Failed to create disk image: {str(e)}")
            return False, ""
    
    def verify_image(self, image_path: str) -> bool:
        """
        Verify the integrity of a disk image using its hash.
        
        Args:
            image_path: Path to the disk image
            
        Returns:
            bool: True if verification successful, False otherwise
        """
        try:
            # Read stored hash
            with open(f"{image_path}.hash", 'r') as f:
                stored_hash = f.read().strip()
            
            # Calculate current hash
            current_hash = self._calculate_hash(image_path)
            
            # Compare hashes
            return stored_hash == current_hash
            
        except Exception as e:
            logging.error(f"Failed to verify disk image: {str(e)}")
            return False
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

class MetadataExtractor:
    """Extracts and manages disk metadata."""
    
    def extract_metadata(self, device_path: str) -> Optional[DiskMetadata]:
        """
        Extract metadata from a disk device.
        
        Args:
            device_path: Path to the device
            
        Returns:
            Optional[DiskMetadata]: Extracted metadata or None if extraction fails
        """
        try:
            # Use system commands to gather disk information
            serial = os.popen(f"udevadm info --query=property --name={device_path} | grep ID_SERIAL").read().strip()
            model = os.popen(f"udevadm info --query=property --name={device_path} | grep ID_MODEL").read().strip()
            size = int(os.popen(f"blockdev --getsize64 {device_path}").read().strip())
            sector_size = int(os.popen(f"blockdev --getss {device_path}").read().strip())
            
            metadata = DiskMetadata(
                serial_number=serial.split('=')[1] if '=' in serial else "Unknown",
                model=model.split('=')[1] if '=' in model else "Unknown",
                size_bytes=size,
                sector_size=sector_size,
                creation_date=datetime.datetime.now(),
                hash_value=self._calculate_device_hash(device_path)
            )
            
            logging.info(f"Successfully extracted metadata for device: {device_path}")
            return metadata
            
        except Exception as e:
            logging.error(f"Failed to extract metadata: {str(e)}")
            return None
    
    def _calculate_device_hash(self, device_path: str) -> str:
        """Calculate hash of the first 1MB of the device for quick identification."""
        sha256_hash = hashlib.sha256()
        with open(device_path, "rb") as f:
            sha256_hash.update(f.read(1024 * 1024))
        return sha256_hash.hexdigest()

class DiskAcquisitionManager:
    """Main class coordinating disk acquisition processes."""
    
    def __init__(self, output_directory: str):
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='disk_acquisition.log'
        )
        
        self.write_blocker = WriteBlocker()
        self.disk_imager = DiskImager(output_directory)
        self.metadata_extractor = MetadataExtractor()
        logging.info("Disk Acquisition Manager initialized")
    
    def acquire_disk(self, device_path: str, image_name: str) -> Dict:
        """
        Perform complete disk acquisition process.
        
        Args:
            device_path: Path to the source device
            image_name: Name for the output image file
            
        Returns:
            Dict: Results of the acquisition process
        """
        results = {
            "success": False,
            "metadata": None,
            "image_path": None,
            "verification": False
        }
        
        try:
            # Enable write blocking
            if not self.write_blocker.block_device(device_path):
                raise Exception("Failed to enable write blocking")
            
            # Extract metadata
            metadata = self.metadata_extractor.extract_metadata(device_path)
            if not metadata:
                raise Exception("Failed to extract metadata")
            results["metadata"] = metadata
            
            # Create disk image
            success, image_path = self.disk_imager.create_image(device_path, image_name)
            if not success:
                raise Exception("Failed to create disk image")
            results["image_path"] = image_path
            
            # Verify image
            if not self.disk_imager.verify_image(image_path):
                raise Exception("Image verification failed")
            results["verification"] = True
            
            results["success"] = True
            logging.info("Disk acquisition completed successfully")
            
        except Exception as e:
            logging.error(f"Disk acquisition failed: {str(e)}")
        
        finally:
            # Always try to disable write blocking
            self.write_blocker.unblock_device(device_path)
        
        return results

def main():
    # Example usage
    manager = DiskAcquisitionManager("/forensics/images")
    results = manager.acquire_disk("/dev/sdb", "evidence_disk_001")
    
    if results["success"]:
        print("Acquisition completed successfully")
        print(f"Image created at: {results['image_path']}")
        print(f"Device metadata: {results['metadata']}")
    else:
        print("Acquisition failed")

if __name__ == "__main__":
    main()
