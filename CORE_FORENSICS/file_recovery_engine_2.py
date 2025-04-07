#!/usr/bin/env python3
"""
Enhanced File Recovery Engine for Digital Forensics
Author: Hardik Jas
"""

import os
import time
import yaml
import hashlib
import logging
from typing import Dict, List, Optional, BinaryIO
from dataclasses import dataclass
from pathlib import Path
import mmap

# Load configuration with error handling
try:
    with open('main_config.yaml') as config_file:
        config = yaml.safe_load(config_file)
except Exception as e:
    print(f"Error loading config: {e}")
    config = {
        'core_forensics': {
            'error_log_directory': 'logs',
            'evidence_directory': 'evidence',
            'recovered_files_directory': 'recovered_files'
        }
    }

# Configure logging with fallback
logs_dir = Path(config['core_forensics'].get('error_log_directory', 'logs'))
logs_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / 'file_recovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('FileRecoveryEngine')

@dataclass
class FileSignature:
    """File signature definition for carving"""
    name: str
    extension: str
    header: bytes
    footer: bytes = None
    max_size: int = 50 * 1024 * 1024  # Default 50MB max file size
    min_size: int = 100  # Minimum file size in bytes

@dataclass
class FileFragment:
    """Represents a file fragment found during carving"""
    offset: int
    data: bytes
    signature_match: str = None
    confidence: float = 0.0

@dataclass
class RecoveredFile:
    """Represents a recovered file with validation metadata"""
    file_path: str
    file_type: str
    original_offset: int
    size: int
    fragments_used: List[int]
    validation_status: Dict
    checksum: str

class FileRecoveryEngine:
    """Main file recovery engine with enhanced performance and reliability"""
    
    # Common file signatures with improved detection
    COMMON_SIGNATURES = [
        FileSignature("Text File", "txt", b'', None, max_size=10*1024*1024),
        FileSignature("JPEG", "jpg", b'\xFF\xD8\xFF', b'\xFF\xD9'),
        FileSignature("PNG", "png", b'\x89PNG\r\n\x1A\n', b'IEND\xAE\x42\x60\x82'),
        FileSignature("PDF", "pdf", b'%PDF', b'%%EOF'),
        FileSignature("ZIP", "zip", b'PK\x03\x04', b'PK\x05\x06'),
        FileSignature("Office Document", "docx", b'PK\x03\x04\x14\x00\x06\x00', None),
        FileSignature("GIF", "gif", b'GIF8', b'\x00\x3B'),
        FileSignature("Windows Executable", "exe", b'MZ', None),
        FileSignature("MP3", "mp3", b'\xFF\xFB', None),
        FileSignature("MP4", "mp4", b'ftypmp4', None),
        FileSignature("Windows Registry", "dat", b'regf', None),
        FileSignature("SQLite Database", "db", b'SQLite format 3', None),
    ]
    
    def __init__(self, case_id: str, max_files: int = 1000, max_runtime: int = 3600):
        self.case_id = case_id
        self.max_files = max_files
        self.max_runtime = max_runtime
        self.recovered_files = []
        self.start_time = None
        
        # Initialize paths from config
        self.evidence_dir = Path(config['core_forensics']['evidence_directory'])
        self.case_dir = self.evidence_dir / f"case_{case_id}"
        self.output_dir = Path(config['core_forensics']['recovered_files_directory']) / f"case_{case_id}"
        self.disk_image_dir = self.case_dir / "disk_images"
        
        # Create directories if they don't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.disk_image_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized recovery for case {case_id}")
        logger.info(f"Output directory: {self.output_dir}")

    def set_limits(self, max_files: int = None, max_runtime: int = None):
        """Update safety limits during operation"""
        if max_files:
            self.max_files = max_files
        if max_runtime:
            self.max_runtime = max_runtime
        logger.info(f"Updated limits - Max files: {self.max_files}, Max runtime: {self.max_runtime}s")

    def _should_stop(self) -> bool:
        """Check if recovery should stop based on safety limits"""
        if not hasattr(self, 'recovered_files') or not hasattr(self, 'start_time'):
            return False
            
        if len(self.recovered_files) >= self.max_files:
            logger.warning(f"Stopping after reaching max files ({self.max_files})")
            return True
        
        if time.time() - self.start_time > self.max_runtime:
            logger.warning(f"Stopping after max runtime ({self.max_runtime}s)")
            return True
        
        return False

    def carve_files(self, disk_image_name: str, 
                   custom_signatures: List[FileSignature] = None,
                   progress_callback=None) -> List[RecoveredFile]:
        """
        Carve files from disk image using signature-based detection
        
        Args:
            disk_image_name: Name of the disk image file (in case's disk_images directory)
            custom_signatures: Optional list of custom file signatures
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of recovered file objects
        """
        self.start_time = time.time()
        self.recovered_files = []
        disk_image_path = self.disk_image_dir / disk_image_name
        self.disk_image_path = str(disk_image_path)
        
        if not disk_image_path.exists():
            raise FileNotFoundError(f"Disk image not found at {disk_image_path}")
        
        logger.info(f"Starting file carving on {disk_image_path}")
        
        # Combine default and custom signatures
        signatures = self.COMMON_SIGNATURES + (custom_signatures or [])
        
        try:
            file_size = disk_image_path.stat().st_size
            
            with open(disk_image_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    potential_files = {}
                    
                    # Process in chunks for progress reporting
                    chunk_size = 10 * 1024 * 1024  # 10MB chunks
                    for offset in range(0, file_size, chunk_size):
                        if self._should_stop():
                            break
                            
                        chunk_end = min(offset + chunk_size, file_size)
                        chunk = mm[offset:chunk_end]
                        
                        self._process_chunk(chunk, offset, signatures, potential_files)
                        
                        if progress_callback:
                            progress = (chunk_end / file_size) * 100
                            progress_callback(progress)
                    
                    # Process any remaining potential files if not stopped
                    if not self._should_stop():
                        self._finalize_potential_files(mm, potential_files)
            
            logger.info(f"File carving complete. Found {len(self.recovered_files)} files.")
            return self.recovered_files
            
        except Exception as e:
            logger.error(f"Error during file carving: {str(e)}", exc_info=True)
            raise RuntimeError(f"File carving failed: {str(e)}") from e

    def _process_chunk(self, chunk: bytes, base_offset: int,
                     signatures: List[FileSignature],
                     potential_files: Dict
                     ):
        """Process a chunk of data looking for file signatures"""
        # Look for file headers
        for sig in signatures:
            pos = 0
            while True:
                match_offset = chunk.find(sig.header, pos)
                if match_offset == -1:
                    break
                absolute_offset = base_offset + match_offset
                potential_files[absolute_offset] = {
                    'signature': sig,
                    'data_collected': bytearray(),
                    'size': 0
                }
                logger.debug(f"Found potential {sig.name} file header at offset {absolute_offset}")
                pos = match_offset + 1
        
        # Look for file footers and complete files
        for sig in [s for s in signatures if s.footer]:
            pos = 0
            while True:
                match_offset = chunk.find(sig.footer, pos)
                if match_offset == -1:
                    break
                
                footer_abs_offset = base_offset + match_offset + len(sig.footer)
                matched_offset = None
                
                # Find the most recent matching header
                for start_offset in sorted(potential_files.keys(), reverse=True):
                    file_data = potential_files[start_offset]
                    if (file_data['signature'] == sig and 
                        start_offset < footer_abs_offset and
                        footer_abs_offset - start_offset <= sig.max_size):
                        
                        matched_offset = start_offset
                        break
                
                # Extract complete file if found
                if matched_offset is not None:
                    file_size = footer_abs_offset - matched_offset
                    if file_size >= sig.min_size:
                        self._extract_file(matched_offset, file_size, sig)
                        potential_files.pop(matched_offset)
                
                pos = match_offset + 1

    def _finalize_potential_files(self, disk_image: mmap.mmap,
                                potential_files: Dict
                                ):
        """Process remaining potential files that might not have footers"""
        for start_offset, file_data in potential_files.items():
            sig = file_data['signature']
            if not sig.footer:
                # Extract a reasonable sized chunk for header-only files
                suggested_size = min(sig.max_size, 1024 * 1024)  # 1MB max
                self._extract_file(start_offset, suggested_size, sig)

    def validate_recovery(self, file: RecoveredFile) -> Dict:
        """Validate recovered file integrity with comprehensive checks"""
        validation = {'file_exists': False}
        
        try:
            file_path = Path(file.file_path)
            if not file_path.exists():
                file.validation_status = validation
                return validation
                
            validation.update({
                'file_exists': True,
                'size_match': file_path.stat().st_size == file.size,
                'format_valid': self._validate_file_format(file),
                'corruption_check': self._check_file_corruption(file),
                'checksum_match': self._verify_checksum(file)
            })
            
            # Calculate overall validation score
            valid_checks = sum(1 for v in validation.values() if v is True)
            validation['score'] = valid_checks / len(validation)
            
            file.validation_status = validation
            return validation
            
        except Exception as e:
            logger.error(f"Validation error for {file.file_path}: {str(e)}")
            validation['error'] = str(e)
            file.validation_status = validation
            return validation

    def _validate_file_format(self, file: RecoveredFile) -> bool:
        """Check if the file matches its claimed format"""
        try:
            with open(file.file_path, 'rb') as f:
                header = f.read(32)  # Read enough bytes for signature detection
                return any(
                    sig.header == header[:len(sig.header)]
                    for sig in self.COMMON_SIGNATURES
                    if sig.name == file.file_type
                )
        except Exception:
            return False

    def _check_file_corruption(self, file: RecoveredFile) -> bool:
        """Check for file corruption based on file type"""
        try:
            ext = os.path.splitext(file.file_path)[1].lower()
            validation_methods = {
                '.jpg': self._validate_jpeg,
                '.jpeg': self._validate_jpeg,
                '.png': self._validate_png,
                '.pdf': self._validate_pdf,
                '.zip': self._validate_zip,
                '.gif': self._validate_gif
            }
            return validation_methods.get(ext, lambda _: True)(file.file_path)
        except Exception:
            return False

    def _verify_checksum(self, file: RecoveredFile) -> bool:
        """Verify the file checksum matches the stored value"""
        try:
            with open(file.file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest() == file.checksum
        except Exception:
            return False

    def _validate_jpeg(self, path: str) -> bool:
        with open(path, 'rb') as f:
            data = f.read()
            return data.startswith(b'\xFF\xD8\xFF') and data.endswith(b'\xFF\xD9')

    def _validate_png(self, path: str) -> bool:
        with open(path, 'rb') as f:
            data = f.read()
            return (data.startswith(b'\x89PNG\r\n\x1A\n') and 
                    b'IEND\xAE\x42\x60\x82' in data)

    def _validate_pdf(self, path: str) -> bool:
        with open(path, 'rb') as f:
            data = f.read()
            return data.startswith(b'%PDF') and b'%%EOF' in data[-1024:]

    def _validate_zip(self, path: str) -> bool:
        with open(path, 'rb') as f:
            return f.read(4) == b'PK\x03\x04'

    def _validate_gif(self, path: str) -> bool:
        with open(path, 'rb') as f:
            data = f.read()
            return data.startswith(b'GIF8') and data.endswith(b'\x00\x3B')

    def reconstruct_fragments(self, fragments: List[FileFragment],
                            target_file_type: str = None) -> List[RecoveredFile]:
        """Reconstruct files from fragments with improved grouping algorithm"""
        try:
            relevant_frags = [f for f in fragments 
                            if not target_file_type or f.signature_match == target_file_type]
            sorted_frags = sorted(relevant_frags, key=lambda x: x.offset)
            
            groups = []
            current_group = []
            
            for frag in sorted_frags:
                if not current_group:
                    current_group.append(frag)
                else:
                    last_end = current_group[-1].offset + len(current_group[-1].data)
                    if abs(frag.offset - last_end) <= 512:  # More generous tolerance
                        current_group.append(frag)
                    else:
                        groups.append(current_group)
                        current_group = [frag]
            
            if current_group:
                groups.append(current_group)
            
            return [self._reconstruct_group(g) for g in groups if g]
            
        except Exception as e:
            logger.error(f"Fragment reconstruction failed: {str(e)}")
            return []

    def _reconstruct_group(self, fragments: List[FileFragment]) -> Optional[RecoveredFile]:
        """Reconstruct a file from a contiguous group of fragments"""
        try:
            first_frag = fragments[0]
            file_type = first_frag.signature_match or "unknown"
            extension = next((s.extension for s in self.COMMON_SIGNATURES 
                            if s.name == file_type), "bin")
            
            file_name = f"reconstructed_{file_type}_{first_frag.offset}.{extension}"
            file_path = self.output_dir / file_name
            
            # Combine fragment data with gap filling
            combined = bytearray()
            prev_end = None
            
            for frag in fragments:
                if prev_end is not None and frag.offset > prev_end:
                    combined.extend(b'\x00' * (frag.offset - prev_end))
                combined.extend(frag.data)
                prev_end = frag.offset + len(frag.data)
            
            with open(file_path, 'wb') as f:
                f.write(combined)
            
            checksum = hashlib.sha256(combined).hexdigest()
            recovered_file = RecoveredFile(
                file_path=str(file_path),
                file_type=file_type,
                original_offset=first_frag.offset,
                size=len(combined),
                fragments_used=[f.offset for f in fragments],
                validation_status={'initial_validation': 'pending'},
                checksum=checksum
            )
            
            self.validate_recovery(recovered_file)
            return recovered_file
            
        except Exception as e:
            logger.error(f"Failed to reconstruct file group: {str(e)}")
            return None
    
    # Example of updated _extract_file method:
    def _extract_file(self, start_offset: int, size: int, signature: FileSignature):
        """Safe file extraction with validation"""
        try:
            # Validate paths
            if not hasattr(self, 'output_dir') or not self.output_dir:
                raise ValueError("Output directory not configured")
                
            output_path = Path(self.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            file_path = output_path / f"{signature.name}_{start_offset}.{signature.extension}"
            
            # Read and write file data
            with open(self.disk_image_path, 'rb') as src, open(file_path, 'wb') as dest:
                src.seek(start_offset)
                dest.write(src.read(size))
            
            # Create recovery record
            with open(file_path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
                
            return RecoveredFile(
                file_path=str(file_path),
                file_type=signature.name,
                original_offset=start_offset,
                size=size,
                fragments_used=[start_offset],
                validation_status={'initial_validation': True},
                checksum=checksum
            )
        except Exception as e:
            logger.error(f"Extraction failed at offset {start_offset}: {str(e)}")
            if 'file_path' in locals() and file_path.exists():
                file_path.unlink()
            raise

# Add to file_recovery_engine_2.py

class FastRecoveryEngine:
    """Optimized file recovery engine with all fixes implemented"""
    
    def __init__(self, output_directory: str, case_id: str, max_files: int = 50, max_runtime: int = 120):
        self.case_id = case_id
        self.max_files = max_files
        self.max_runtime = max_runtime
        self.recovered_files = []
        self.start_time = None
        
        # Initialize paths
        self.output_dir = Path(output_directory)
        self.disk_image_dir = self.output_dir.parent / "disk_images"
        self.disk_image_path = None
        
        # Create directories if they don't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.disk_image_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized FastRecoveryEngine for case {case_id}")

    def _extract_file(self, start_offset: int, size: int, signature: FileSignature):
        """Safe file extraction with full error handling"""
        try:
            if not self.disk_image_path:
                raise ValueError("Disk image path not set")
                
            file_path = self.output_dir / f"{signature.name}_{start_offset}.{signature.extension}"
            
            # Read in chunks to handle large files
            with open(str(self.disk_image_path), 'rb') as src, open(str(file_path), 'wb') as dest:
                src.seek(start_offset)
                remaining = size
                chunk_size = 1024 * 1024  # 1MB chunks
                
                while remaining > 0:
                    chunk = src.read(min(remaining, chunk_size))
                    if not chunk:
                        break
                    dest.write(chunk)
                    remaining -= len(chunk)
            
            # Verify extraction
            if not file_path.exists() or file_path.stat().st_size == 0:
                raise ValueError("File extraction failed - empty output")
                
            # Calculate checksum
            with open(str(file_path), 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
                
            # Create recovery record
            recovered_file = RecoveredFile(
                file_path=str(file_path),
                file_type=signature.name,
                original_offset=start_offset,
                size=size,
                fragments_used=[start_offset],
                validation_status={'initial_validation': True},
                checksum=checksum
            )
            
            self.recovered_files.append(recovered_file)
            return recovered_file
            
        except Exception as e:
            logger.error(f"Extraction failed at offset {start_offset}: {str(e)}")
            if 'file_path' in locals() and file_path.exists():
                file_path.unlink()
            raise

    def carve_files(self, disk_image_name: str, custom_signatures=None, progress_callback=None):
        """Enhanced fast carving with comprehensive error handling"""
        self.start_time = time.time()
        self.recovered_files = []
        self.disk_image_path = self.disk_image_dir / disk_image_name
        
        # Validate inputs
        if not self.disk_image_path.exists():
            raise FileNotFoundError(f"Disk image not found at {self.disk_image_path}")
            
        # Signature configuration
        signatures = [
            FileSignature("JPEG", "jpg", b'\xFF\xD8\xFF', b'\xFF\xD9', max_size=20*1024*1024),
            FileSignature("PDF", "pdf", b'%PDF', b'%%EOF', max_size=50*1024*1024),
            FileSignature("ZIP", "zip", b'PK\x03\x04', b'PK\x05\x06'),
            FileSignature("Office Document", "docx", b'PK\x03\x04\x14\x00\x06\x00'),
            FileSignature("PNG", "png", b'\x89PNG\r\n\x1A\n', b'IEND\xAE\x42\x60\x82'),
            FileSignature("Windows Executable", "exe", b'MZ'),
            FileSignature("SQLite Database", "db", b'SQLite format 3')
        ] + (custom_signatures or [])
        
        try:
            file_size = os.path.getsize(self.disk_image_path)
            max_bytes_to_scan = min(file_size, 200 * 1024 * 1024)  # First 200MB max
            
            with open(str(self.disk_image_path), 'rb') as f:
                with mmap.mmap(f.fileno(), max_bytes_to_scan, access=mmap.ACCESS_READ) as mm:
                    chunk_size = 10 * 1024 * 1024  # 10MB chunks
                    
                    for offset in range(0, max_bytes_to_scan, chunk_size):
                        if self._should_stop():
                            break
                            
                        chunk_end = min(offset + chunk_size, max_bytes_to_scan)
                        chunk = mm[offset:chunk_end]
                        
                        # Process all signatures in this chunk
                        for sig in signatures:
                            if len(self.recovered_files) >= self.max_files:
                                break
                                
                            pos = 0
                            while True:
                                header_pos = chunk.find(sig.header, pos)
                                if header_pos == -1:
                                    break
                                    
                                abs_offset = offset + header_pos
                                
                                # Determine file size
                                if sig.footer:
                                    footer_pos = chunk.find(sig.footer, header_pos + len(sig.header))
                                    if footer_pos != -1:
                                        file_size = (footer_pos - header_pos) + len(sig.footer)
                                    else:
                                        file_size = sig.max_size
                                else:
                                    file_size = sig.max_size
                                
                                # Limit to remaining data
                                file_size = min(file_size, max_bytes_to_scan - abs_offset)
                                
                                try:
                                    self._extract_file(abs_offset, file_size, sig)
                                except Exception as e:
                                    logger.warning(f"Skipping file at offset {abs_offset}: {str(e)}")
                                
                                pos = header_pos + 1
                        
                        # Update progress
                        if progress_callback:
                            progress = (chunk_end / max_bytes_to_scan) * 100
                            progress_callback(progress)
            
            logger.info(f"Recovered {len(self.recovered_files)} files (scanned {max_bytes_to_scan/1024/1024:.1f}MB)")
            return self.recovered_files
            
        except Exception as e:
            logger.error(f"Carving failed: {str(e)}")
            raise RuntimeError(f"File carving failed: {str(e)}") from e

    def _should_stop(self):
        """Check if we should stop based on limits"""
        if len(self.recovered_files) >= self.max_files:
            logger.info(f"Reached max files limit ({self.max_files})")
            return True
            
        if time.time() - self.start_time > self.max_runtime:
            logger.info(f"Reached max runtime ({self.max_runtime}s)")
            return True
            
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id", help="Case ID for organization")
    parser.add_argument("image_name", help="Name of disk image file (in case's disk_images directory)")
    parser.add_argument("--max-files", type=int, default=1000, help="Maximum files to recover")
    parser.add_argument("--max-runtime", type=int, default=3600, help="Maximum runtime in seconds")
    args = parser.parse_args()
    
    engine = FileRecoveryEngine(
        case_id=args.case_id,
        max_files=args.max_files,
        max_runtime=args.max_runtime
    )
    engine.carve_files(args.image_name)
