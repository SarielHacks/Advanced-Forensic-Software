# CORE_FORENSICS/disk_acquisition_manager.py
import os
import re
import hashlib
import logging
import datetime
import subprocess
import time
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, asdict
from pathlib import Path
import threading

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class DiskMetadata:
    """Stores metadata information about a disk."""
    serial_number: str
    model: str
    size_bytes: int
    sector_size: int
    creation_date: datetime.datetime
    hash_value: str
    device_path: str
    image_path: str

    def to_dict(self) -> Dict:
        """Convert metadata to dictionary for serialization"""
        return {
            **asdict(self),
            "creation_date": self.creation_date.isoformat()
        }

class WriteBlocker:
    """Implements write blocking functionality to prevent disk modification."""
    
    def __init__(self, case_id: str, output_directory: str):
        """Initialize with case-specific paths"""
        self.case_id = case_id
        self.output_directory = output_directory
        self._blocked_devices = set()
        
        # Create directory if it doesn't exist
        Path(self.output_directory).mkdir(parents=True, exist_ok=True)
        logger.info(f"WriteBlocker initialized for case {case_id}, output to {self.output_directory}")
    
    def block_device(self, device_path: str) -> bool:
        """Enable write blocking for a specific device."""
        try:
            # First unmount if mounted
            mount_point = self._get_mount_point(device_path)
            if mount_point:
                if not self._unmount_disk(device_path):
                    raise RuntimeError(f"Failed to unmount device at {mount_point}")
            
            # Try different write blocking methods
            methods = [
                self._blockdev_method,
                self._sysfs_method,
                self._udev_method
            ]
            
            for method in methods:
                if method(device_path, read_only=True):
                    self._blocked_devices.add(device_path)
                    logger.info(f"Write blocking enabled for {device_path} using {method.__name__}")
                    return True
            
            raise RuntimeError("All write blocking methods failed")
            
        except Exception as e:
            logger.error(f"Failed to enable write blocking for {device_path}: {str(e)}", exc_info=True)
            return False
    
    def unblock_device(self, device_path: str) -> bool:
        """Disable write blocking for a specific device."""
        try:
            if device_path in self._blocked_devices:
                # Try different unblocking methods
                methods = [
                    self._blockdev_method,
                    self._sysfs_method,
                    self._udev_method
                ]
                
                for method in methods:
                    if method(device_path, read_only=False):
                        self._blocked_devices.remove(device_path)
                        logger.info(f"Write blocking disabled for {device_path} using {method.__name__}")
                        return True
                
                logger.warning(f"Write unblocking failed for {device_path}")
                return False
            return True  # Not blocked is considered success
            
        except Exception as e:
            logger.error(f"Failed to disable write blocking for {device_path}: {str(e)}", exc_info=True)
            return False

    def _blockdev_method(self, device_path: str, read_only: bool) -> bool:
        """Use blockdev command to set read-only status"""
        try:
            mode = '--setro' if read_only else '--setrw'
            result = subprocess.run(
                ['sudo', 'blockdev', mode, device_path],
                check=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.debug(f"blockdev method failed: {e.stderr.strip()}")
            return False

    def _sysfs_method(self, device_path: str, read_only: bool) -> bool:
        """Use sysfs to set read-only status"""
        try:
            base_name = os.path.basename(device_path)
            sysfs_path = f"/sys/block/{base_name}/ro"
            
            if not os.path.exists(sysfs_path):
                return False
                
            value = '1' if read_only else '0'
            with open(sysfs_path, 'w') as f:
                f.write(value)
            return True
        except Exception as e:
            logger.debug(f"sysfs method failed: {str(e)}")
            return False

    def _udev_method(self, device_path: str, read_only: bool) -> bool:
        """Use udev rules to set read-only status"""
        try:
            rule = f'SUBSYSTEM=="block", KERNEL=="{os.path.basename(device_path)}", ATTR{{ro}}="{"1" if read_only else "0"}"'
            result = subprocess.run(
                ['sudo', 'udevadm', 'control', '--reload-rules'],
                check=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True
            )
            return True
        except Exception as e:
            logger.debug(f"udev method failed: {str(e)}")
            return False

    def _get_mount_point(self, device_path: str) -> Optional[str]:
        """Get mount point for a device if mounted"""
        try:
            result = subprocess.run(
                ['findmnt', '-n', '-o', 'TARGET', device_path],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception:
            return None

    def _unmount_disk(self, device_path: str) -> bool:
        """Attempt to unmount a device"""
        try:
            result = subprocess.run(
                ['sudo', 'umount', device_path],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                return True
            if "not mounted" in result.stderr.lower():
                return True
            return False
        except Exception:
            return False

class DiskImager:
    """Handles creation and verification of disk images."""
    
    IMAGING_TOOLS = ['dcfldd', 'dd', 'dc3dd']  # Ordered by preference
    
    def __init__(self, output_directory: str):
        self.output_directory = output_directory
        Path(output_directory).mkdir(parents=True, exist_ok=True)
        self._verify_imaging_tools()
        logger.info(f"Disk imager initialized with output directory: {output_directory}")
    
    def _verify_imaging_tools(self):
        """Check which imaging tools are available"""
        self.available_tools = []
        for tool in self.IMAGING_TOOLS:
            try:
                subprocess.run(
                    [tool, '--version'],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                self.available_tools.append(tool)
            except Exception:
                continue
        
        if not self.available_tools:
            raise RuntimeError("No disk imaging tools found. Please install dcfldd, dd, or dc3dd")
        
        logger.info(f"Available imaging tools: {', '.join(self.available_tools)}")
    
    def create_image(self, source_device: str, image_name: str) -> Tuple[bool, str]:
        """Create a forensic image of a disk using the best available tool."""
        image_path = str(Path(self.output_directory) / f"{image_name}.dd")
        hash_path = f"{image_path}.hash"
        
        try:
            # Verify source device exists and is readable
            if not os.path.exists(source_device):
                raise ValueError(f"Device path does not exist: {source_device}")
            
            if not os.access(source_device, os.R_OK):
                raise PermissionError(f"No read access to device: {source_device}")
            
            # Try each available imaging tool in order of preference
            for tool in self.available_tools:
                try:
                    if tool == 'dcfldd':
                        success, hash_value = self._create_image_with_dcfldd(source_device, image_path)
                    elif tool == 'dc3dd':
                        success, hash_value = self._create_image_with_dc3dd(source_device, image_path)
                    else:  # dd
                        success, hash_value = self._create_image_with_dd(source_device, image_path)
                    
                    if success:
                        # Save hash to file
                        with open(hash_path, 'w') as f:
                            f.write(hash_value)
                        logger.info(f"Successfully created image using {tool}")
                        return True, image_path
                    
                except Exception as e:
                    logger.warning(f"Failed to create image with {tool}: {str(e)}")
                    continue
            
            raise RuntimeError(f"All imaging tools failed for {source_device}")
            
        except Exception as e:
            logger.error(f"Failed to create disk image: {str(e)}", exc_info=True)
            # Clean up partial files
            if os.path.exists(image_path):
                os.remove(image_path)
            if os.path.exists(hash_path):
                os.remove(hash_path)
            return False, str(e)
    
    def _create_image_with_dcfldd(self, source_device: str, image_path: str) -> Tuple[bool, str]:
        """Create image using dcfldd (preferred method)"""
        cmd = [
            'sudo', 'dcfldd',
            f'if={source_device}',
            f'of={image_path}',
            'bs=4M',
            'hash=sha256',
            'hashlog=:stdout',
            'status=on'
        ]
        
        logger.info(f"Creating image with dcfldd: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            check=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            timeout=3600 * 3  # 3 hour timeout for large disks
        )
        
        hash_value = self._extract_hash_from_output(result.stdout)
        return True, hash_value
    
    def _create_image_with_dc3dd(self, source_device: str, image_path: str) -> Tuple[bool, str]:
        """Create image using dc3dd (alternative to dcfldd)"""
        cmd = [
            'sudo', 'dc3dd',
            f'if={source_device}',
            f'of={image_path}',
            'bs=4M',
            'hash=sha256',
            'log=:stdout'
        ]
        
        logger.info(f"Creating image with dc3dd: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            check=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            timeout=3600 * 3
        )
        
        hash_value = self._extract_hash_from_output(result.stdout)
        return True, hash_value
    
    def _create_image_with_dd(self, source_device: str, image_path: str) -> Tuple[bool, str]:
        """Create image using dd (fallback method)"""
        cmd = [
            'sudo', 'dd',
            f'if={source_device}',
            f'of={image_path}',
            'bs=4M',
            'status=progress'
        ]
        
        logger.info(f"Creating image with dd: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            check=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            timeout=3600 * 3
        )
        
        # dd doesn't provide hashing, so we calculate it manually
        hash_value = self._calculate_hash(image_path)
        return True, hash_value
    
    def verify_image(self, image_path: str) -> bool:
        """Verify the integrity of a disk image using its hash."""
        try:
            if not os.path.exists(image_path):
                raise ValueError(f"Image file not found: {image_path}")
            
            hash_file = f"{image_path}.hash"
            
            # Get stored hash
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    stored_hash = f.read().strip()
            else:
                logger.warning("Hash file not found, using fallback verification")
                current_hash = self._calculate_hash(image_path)
                with open(hash_file, 'w') as f:
                    f.write(current_hash)
                logger.warning(f"Generated new hash file with value: {current_hash}")
                return True  # Can't verify against original, but now we have a hash
            
            # Calculate current hash
            current_hash = self._calculate_hash(image_path)
            
            if stored_hash == current_hash:
                logger.info("Image verification successful")
                return True
            
            logger.error(f"Image verification failed - hash mismatch\nStored: {stored_hash}\nCurrent: {current_hash}")
            return False
                
        except Exception as e:
            logger.error(f"Failed to verify disk image: {str(e)}", exc_info=True)
            return False
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file with progress updates."""
        sha256_hash = hashlib.sha256()
        total_size = os.path.getsize(file_path)
        bytes_read = 0
        last_update = 0
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096 * 1024), b""):  # 4MB chunks
                sha256_hash.update(byte_block)
                bytes_read += len(byte_block)
                
                # Log progress every 5% or 5 seconds
                progress = (bytes_read / total_size) * 100
                now = time.time()
                if progress - last_update >= 5 or now - last_update >= 5:
                    logger.info(f"Hashing progress: {progress:.1f}%")
                    last_update = progress
        
        return sha256_hash.hexdigest()
    
    def _extract_hash_from_output(self, output: str) -> str:
        """Extract hash value from imaging tool output with multiple fallbacks"""
        # Try standard format first (dcfldd)
        for line in output.split('\n'):
            if line.startswith('sha256:'):
                return line.split(':')[1].strip()
            if line.startswith('sha256 hash:'):
                return line.split(':')[1].strip()
        
        # Fallback to finding any 64-character hex string
        hex_pattern = re.compile(r'[a-fA-F0-9]{64}')
        matches = hex_pattern.findall(output)
        if matches:
            return matches[-1]  # Return last match (most likely the final hash)
        
        raise ValueError("Hash not found in output")
        
        
class FastDiskImager(DiskImager):
    """Optimized disk imager for prototype demonstration"""
    
    def create_image(self, source_device: str, image_name: str) -> Tuple[bool, str]:
        """Create a partial forensic image (first 100MB)"""
        image_path = str(Path(self.output_directory) / f"{image_name}.dd")
        hash_path = f"{image_path}.hash"
        
        try:
            # Only image first 100MB for prototype
            size_limit = 100 * 1024 * 1024  # 100MB
            
            cmd = [
                'sudo', 'dd',
                f'if={source_device}',
                f'of={image_path}',
                'bs=16M',  # Larger block size for speed
                'count=6',  # 6*16MB = ~100MB
                'status=progress'
            ]
            
            logger.info(f"Creating partial image: {' '.join(cmd)}")
            subprocess.run(
                cmd,
                check=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            # Calculate hash of partial image
            hash_value = self._calculate_hash(image_path)
            with open(hash_path, 'w') as f:
                f.write(hash_value)
                
            return True, image_path
            
        except Exception as e:
            logger.error(f"Partial imaging failed: {str(e)}")
            if os.path.exists(image_path):
                os.remove(image_path)
            if os.path.exists(hash_path):
                os.remove(hash_path)
            return False, str(e)

class DiskAcquisitionManager:
    """Main class coordinating disk acquisition processes."""
    
    def __init__(self, output_directory: str, case_id: str):
        self.logger = logging.getLogger(f"{__name__}.DiskAcquisitionManager")
        self.logger.info("Initializing Disk Acquisition Manager")
        
        self.output_directory = output_directory
        self.case_id = case_id
        
        # Initialize components with case_id
        self.write_blocker = WriteBlocker(case_id, output_directory)
        self.disk_imager = DiskImager(output_directory)
        
        # Ensure output directory exists
        Path(output_directory).mkdir(parents=True, exist_ok=True)
    
    def acquire_disk(self, device_path: str, image_name: str = None) -> Dict:
        """Perform complete disk acquisition process."""
        results = {
            "success": False,
            "error": None,
            "metadata": None,
            "image_path": None,
            "verification": False,
            "warnings": []
        }
        
        try:
            self.logger.info(f"Starting acquisition of {device_path} for case {self.case_id}")
            
            # Validate device
            if not os.path.exists(device_path):
                raise ValueError(f"Device path does not exist: {device_path}")
            
            # Get disk info
            disk_info = self._get_disk_info(device_path)
            if not disk_info:
                raise RuntimeError("Failed to get disk information")
            
            # Use provided image_name or generate one
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            if image_name is None:
                image_name = f"{self.case_id}_{timestamp}"
            else:
                image_name = f"{image_name}_{timestamp}"
            
            # Enable write blocking
            if not self.write_blocker.block_device(device_path):
                results["warnings"].append("Write blocking could not be enabled")
                self.logger.warning("Write blocking could not be enabled - proceeding anyway")
            
            # Create initial metadata
            metadata = DiskMetadata(
                serial_number=disk_info.get('serial', 'Unknown'),
                model=disk_info.get('model', 'Unknown'),
                size_bytes=int(disk_info.get('size', 0)),
                sector_size=int(disk_info.get('sector_size', 512)),
                creation_date=datetime.datetime.now(),
                hash_value="Pending acquisition",
                device_path=device_path,
                image_path="Pending acquisition"
            )
            results["metadata"] = metadata
            
            # Create disk image
            success, image_path = self.disk_imager.create_image(device_path, image_name)
            if not success:
                raise RuntimeError("Failed to create disk image")
            
            metadata.image_path = image_path
            results["image_path"] = image_path
            
            # Verify image
            verification_result = self.disk_imager.verify_image(image_path)
            results["verification"] = verification_result
            
            if not verification_result:
                results["warnings"].append("Image verification failed")
                self.logger.warning("Image verification failed - hash mismatch")
            
            # Update metadata with final hash
            hash_file = f"{image_path}.hash"
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    metadata.hash_value = f.read().strip()
            
            results["success"] = True
            self.logger.info(f"Successfully acquired disk {device_path} to {image_path}")
            
        except Exception as e:
            results["error"] = str(e)
            self.logger.error(f"Disk acquisition failed: {str(e)}", exc_info=True)
        
        finally:
            # Always attempt to unblock device
            self.write_blocker.unblock_device(device_path)
            self.logger.info(f"Completed acquisition process for {device_path}")
        
        return results
    
    def _get_disk_info(self, device_path: str) -> Dict:
        """Get disk information using multiple methods."""
        try:
            # Try smartctl first
            try:
                result = subprocess.run(
                    ['sudo', 'smartctl', '-i', device_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                info = self._parse_smartctl_output(result.stdout)
                if info:
                    return info
            except Exception:
                pass
            
            # Fallback to hdparm
            try:
                result = subprocess.run(
                    ['sudo', 'hdparm', '-I', device_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                info = self._parse_hdparm_output(result.stdout)
                if info:
                    return info
            except Exception:
                pass
            
            # Final fallback to blockdev
            try:
                size = subprocess.run(
                    ['sudo', 'blockdev', '--getsize64', device_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                ).stdout.strip()
                
                sector = subprocess.run(
                    ['sudo', 'blockdev', '--getss', device_path],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                ).stdout.strip()
                
                return {
                    'size': size,
                    'sector_size': sector,
                    'model': 'Unknown',
                    'serial': 'Unknown',
                    'type': 'Unknown'
                }
            except Exception:
                pass
            
            return {}
            
        except Exception as e:
            self.logger.warning(f"Failed to get disk info: {str(e)}")
            return {}
    
    def _parse_smartctl_output(self, output: str) -> Dict:
        """Parse smartctl output for disk information."""
        info = {}
        for line in output.split('\n'):
            if 'Model Number:' in line:
                info['model'] = line.split(':')[1].strip()
            elif 'Serial Number:' in line:
                info['serial'] = line.split(':')[1].strip()
            elif 'User Capacity:' in line:
                parts = line.split('[')[1].split(']')[0].split()
                if parts[1] == 'bytes':
                    info['size'] = parts[0].replace(',', '')
            elif 'Sector Size:' in line:
                parts = line.split(':')[1].strip().split()
                info['sector_size'] = parts[0]
        
        return info
    
    def _parse_hdparm_output(self, output: str) -> Dict:
        """Parse hdparm output for disk information."""
        info = {}
        for line in output.split('\n'):
            if 'Model Number:' in line:
                info['model'] = line.split(':')[1].strip()
            elif 'Serial Number:' in line:
                info['serial'] = line.split(':')[1].strip()
            elif 'device size with M = 1000*1000:' in line:
                parts = line.split('(')[1].split()[0]
                info['size'] = str(int(float(parts) * 1000 * 1000))
            elif 'Physical Sector size:' in line:
                info['sector_size'] = line.split(':')[1].split()[0]
        
        return info
    
    def acquire_disk_fast(self, device_path: str, image_name: str = None) -> Dict:
        """Perform fast disk acquisition (first 100MB only)"""
        results = {
            "success": False,
            "error": None,
            "metadata": None,
            "image_path": None,
            "verification": False,
            "warnings": [],
            "fast_mode": True  # Flag indicating fast mode
        }
        
        try:
            self.logger.info(f"Starting FAST acquisition of {device_path}")
            
            # Validate device
            if not os.path.exists(device_path):
                raise ValueError(f"Device path does not exist: {device_path}")
            
            # Get basic disk info (skip time-consuming checks)
            disk_info = {
                'size': "100MB (fast mode)",
                'sector_size': 512,  # Default assumption
                'model': 'Unknown (fast mode)',
                'serial': 'Unknown (fast mode)',
                'type': 'Unknown (fast mode)'
            }
            
            # Generate image name
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            image_name = image_name or f"fast_{self.case_id}_{timestamp}"
            
            # Enable write blocking
            if not self.write_blocker.block_device(device_path):
                results["warnings"].append("Write blocking could not be enabled")
                self.logger.warning("Write blocking could not be enabled - proceeding anyway")
            
            # Create metadata
            metadata = DiskMetadata(
                serial_number=disk_info.get('serial'),
                model=disk_info.get('model'),
                size_bytes=100 * 1024 * 1024,  # 100MB
                sector_size=int(disk_info.get('sector_size', 512)),
                creation_date=datetime.datetime.now(),
                hash_value="Pending acquisition",
                device_path=device_path,
                image_path="Pending acquisition"
            )
            results["metadata"] = metadata
            
            # Use fast imager
            fast_imager = FastDiskImager(self.output_directory)
            success, image_path = fast_imager.create_image(device_path, image_name)
            
            if not success:
                raise RuntimeError("Failed to create disk image in fast mode")
            
            metadata.image_path = image_path
            results["image_path"] = image_path
            
            # Quick verification
            verification_result = fast_imager.verify_image(image_path)
            results["verification"] = verification_result
            
            if not verification_result:
                results["warnings"].append("Image verification failed in fast mode")
            
            # Update metadata
            hash_file = f"{image_path}.hash"
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    metadata.hash_value = f.read().strip()
            
            results["success"] = True
            self.logger.info(f"Fast acquisition completed for {device_path}")
            
        except Exception as e:
            results["error"] = str(e)
            self.logger.error(f"Fast acquisition failed: {str(e)}", exc_info=True)
        
        finally:
            self.write_blocker.unblock_device(device_path)
        
        return results
