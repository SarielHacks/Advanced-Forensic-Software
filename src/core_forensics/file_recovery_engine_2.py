#!/usr/bin/env python3
"""
file_recovery_engine.py - Core file recovery module for digital forensics platform
Author: Hardik Jas
Purpose: Provides file carving, recovery validation, and fragment reconstruction capabilities
"""

import os
import struct
import hashlib
import logging
import binascii
from typing import Dict, List, Tuple, Optional, BinaryIO, Set
from dataclasses import dataclass
import concurrent.futures

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='file_recovery.log'
)
logger = logging.getLogger('file_recovery_engine')

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
    """Represents a recovered file"""
    file_path: str
    file_type: str
    original_offset: int
    size: bytes
    fragments_used: List[int]
    validation_status: Dict
    checksum: str


class FileRecoveryEngine:
    """Main file recovery engine implementing carving, validation and reconstruction"""
    
    # Common file signatures (header and footer patterns)
    COMMON_SIGNATURES = [
        FileSignature("JPEG", "jpg", b'\xFF\xD8\xFF', b'\xFF\xD9'),
        FileSignature("PNG", "png", b'\x89PNG\r\n\x1A\n', b'IEND\xAE\x42\x60\x82'),
        FileSignature("PDF", "pdf", b'%PDF', b'%%EOF'),
        FileSignature("ZIP", "zip", b'PK\x03\x04', b'PK\x05\x06'),
        FileSignature("Office Document", "docx", b'PK\x03\x04\x14\x00\x06\x00', None),
        FileSignature("GIF", "gif", b'GIF8', b'\x00\x3B'),
        FileSignature("Windows Executable", "exe", b'MZ', None),
        FileSignature("MP3", "mp3", b'\xFF\xFB', None),
        FileSignature("MP4", "mp4", b'ftypmp4', None),
    ]
    
    def __init__(self, output_dir: str = "recovered_files"):
        """Initialize the file recovery engine"""
        self.output_dir = output_dir
        self.recovered_files = []
        self.fragments = []
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        logger.info(f"File Recovery Engine initialized with output directory: {output_dir}")

    def carve_files(self, disk_image_path: str, custom_signatures: List[FileSignature] = None) -> List[RecoveredFile]:
        """
        Carve files from disk image using signature-based detection
        
        Args:
            disk_image_path: Path to the disk image
            custom_signatures: Optional list of custom file signatures to use
            
        Returns:
            List of recovered file objects
        """
        logger.info(f"Starting file carving on {disk_image_path}")
        
        # Combine default and custom signatures if provided
        signatures = self.COMMON_SIGNATURES
        if custom_signatures:
            signatures.extend(custom_signatures)
            
        recovered_files = []
        self.fragments = []
        
        try:
            # Get file size
            file_size = os.path.getsize(disk_image_path)
            
            with open(disk_image_path, 'rb') as disk_image:
                # Process the image in chunks to handle large files
                chunk_size = 10 * 1024 * 1024  # 10MB chunks
                buffer = bytearray(chunk_size)
                
                # Keep track of potential file starts
                potential_files = {}
                
                offset = 0
                while offset < file_size:
                    # Read chunk into buffer
                    bytes_read = disk_image.readinto(buffer)
                    if bytes_read == 0:
                        break
                        
                    # Search for signatures in this chunk
                    chunk_data = buffer[:bytes_read]
                    self._process_chunk(chunk_data, offset, signatures, potential_files, recovered_files)
                    
                    offset += bytes_read
                
                # Process any remaining potential files
                self._finalize_potential_files(disk_image, potential_files, recovered_files)
                
        except Exception as e:
            logger.error(f"Error during file carving: {str(e)}")
            raise
            
        logger.info(f"File carving complete. Found {len(recovered_files)} files.")
        return recovered_files
        
    def _process_chunk(self, chunk_data: bytes, base_offset: int, 
                      signatures: List[FileSignature], 
                      potential_files: Dict, 
                      recovered_files: List[RecoveredFile]):
        """Process a chunk of data looking for file signatures"""
        
        # Look for file headers
        for sig in signatures:
            for match_offset in self._find_all_occurrences(chunk_data, sig.header):
                absolute_offset = base_offset + match_offset
                # Record start of potential file
                potential_files[absolute_offset] = {
                    'signature': sig,
                    'data_collected': bytearray(),
                    'size': 0
                }
                logger.debug(f"Found potential {sig.name} file header at offset {absolute_offset}")
        
        # Look for file footers and complete files
        for sig in signatures:
            if sig.footer:
                for match_offset in self._find_all_occurrences(chunk_data, sig.footer):
                    footer_abs_offset = base_offset + match_offset + len(sig.footer)
                    
                    # Find matching header
                    matched_header = None
                    matched_offset = None
                    
                    for start_offset, file_data in potential_files.items():
                        if (file_data['signature'] == sig and 
                            start_offset < footer_abs_offset and
                            footer_abs_offset - start_offset <= sig.max_size):
                            
                            if matched_header is None or start_offset > matched_offset:
                                matched_header = file_data
                                matched_offset = start_offset
                    
                    # If matching header found, extract file
                    if matched_header and matched_offset:
                        file_size = footer_abs_offset - matched_offset
                        
                        if file_size >= sig.min_size:
                            # This is a complete file, extract it
                            self._extract_file(matched_offset, file_size, sig, recovered_files)
                            # Remove from potential files
                            potential_files.pop(matched_offset, None)
        
    def _finalize_potential_files(self, disk_image: BinaryIO, 
                               potential_files: Dict, 
                               recovered_files: List[RecoveredFile]):
        """Process remaining potential files that might not have footers"""
        
        for start_offset, file_data in potential_files.items():
            sig = file_data['signature']
            
            # For files without footers, try to determine a reasonable size
            if not sig.footer:
                # Extract a reasonable sized chunk
                suggested_size = min(sig.max_size, 1024 * 1024)  # Default to 1MB max for headerless files
                self._extract_file(start_offset, suggested_size, sig, recovered_files)
                
    def _extract_file(self, start_offset: int, size: int, 
                    signature: FileSignature, 
                    recovered_files: List[RecoveredFile]):
        """Extract a file from the image and save it"""
        
        try:
            # Generate a unique filename
            file_name = f"{signature.name}_{start_offset}.{signature.extension}"
            file_path = os.path.join(self.output_dir, file_name)
            
            # Extract the file data
            with open(self.current_image_path, 'rb') as disk_image:
                disk_image.seek(start_offset)
                file_data = disk_image.read(size)
            
            # Save the file
            with open(file_path, 'wb') as output_file:
                output_file.write(file_data)
            
            # Generate checksum
            checksum = hashlib.sha256(file_data).hexdigest()
            
            # Create the recovered file object
            recovered_file = RecoveredFile(
                file_path=file_path,
                file_type=signature.name,
                original_offset=start_offset,
                size=size,
                fragments_used=[start_offset],
                validation_status={'initial_validation': 'pending'},
                checksum=checksum
            )
            
            # Add to the list of recovered files
            recovered_files.append(recovered_file)
            
            logger.info(f"Extracted {signature.name} file of size {size} bytes from offset {start_offset}")
            
            # Validate the file
            self.validate_recovery(recovered_file)
            
        except Exception as e:
            logger.error(f"Error extracting file at offset {start_offset}: {str(e)}")
    
    def _find_all_occurrences(self, data: bytes, pattern: bytes) -> List[int]:
        """Find all occurrences of a pattern in data"""
        matches = []
        start = 0
        
        while True:
            start = data.find(pattern, start)
            if start == -1:
                break
            matches.append(start)
            start += 1
            
        return matches
    
    def validate_recovery(self, file: RecoveredFile) -> Dict:
        """
        Validate recovered file integrity
        
        Args:
            file: RecoveredFile object to validate
            
        Returns:
            Validation results dictionary
        """
        validation = {}
        
        try:
            # Check if file exists
            if not os.path.exists(file.file_path):
                validation['file_exists'] = False
                file.validation_status = validation
                return validation
                
            validation['file_exists'] = True
            
            # Check file size
            actual_size = os.path.getsize(file.file_path)
            validation['size_match'] = actual_size == file.size
            
            # Validate file format
            validation['format_valid'] = self._validate_file_format(file)
            
            # Check for corruption
            validation['corruption_check'] = self._check_file_corruption(file)
            
            # Verify checksum
            with open(file.file_path, 'rb') as f:
                data = f.read()
                current_checksum = hashlib.sha256(data).hexdigest()
                validation['checksum_match'] = current_checksum == file.checksum
            
            # Calculate overall validation score
            valid_checks = sum(1 for check in validation.values() if check is True)
            total_checks = len(validation)
            validation['score'] = valid_checks / total_checks if total_checks > 0 else 0
            
            # Update file validation status
            file.validation_status = validation
            
            logger.info(f"Validation for {file.file_path}: Score {validation['score']}")
            
        except Exception as e:
            logger.error(f"Error during file validation: {str(e)}")
            validation['error'] = str(e)
            file.validation_status = validation
            
        return validation
    
    def _validate_file_format(self, file: RecoveredFile) -> bool:
        """Check if the file matches its claimed format"""
        try:
            with open(file.file_path, 'rb') as f:
                data = f.read(100)  # Read the beginning of the file
                
                # Try to find a matching signature
                for sig in self.COMMON_SIGNATURES:
                    if sig.name == file.file_type and data.startswith(sig.header):
                        return True
                        
            return False
        except Exception as e:
            logger.error(f"Error validating file format: {str(e)}")
            return False
    
    def _check_file_corruption(self, file: RecoveredFile) -> bool:
        """
        Basic check for file corruption - varies by file type
        Returns True if file appears to be non-corrupted
        """
        try:
            extension = os.path.splitext(file.file_path)[1].lower()
            
            # Basic format-specific validation
            if extension == '.jpg' or extension == '.jpeg':
                return self._validate_jpeg(file.file_path)
            elif extension == '.png':
                return self._validate_png(file.file_path)
            elif extension == '.pdf':
                return self._validate_pdf(file.file_path)
            elif extension == '.zip':
                return self._validate_zip(file.file_path)
                
            # For other file types, do a basic check
            return True
            
        except Exception as e:
            logger.error(f"Error checking file corruption: {str(e)}")
            return False
    
    def _validate_jpeg(self, file_path: str) -> bool:
        """Validate JPEG file format"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                # Check for JPEG header and footer
                if not data.startswith(b'\xFF\xD8\xFF'):
                    return False
                    
                if not data.endswith(b'\xFF\xD9'):
                    return False
                    
                # Additional checks could be added here
                    
                return True
        except Exception:
            return False
    
    def _validate_png(self, file_path: str) -> bool:
        """Validate PNG file format"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                # Check for PNG signature
                if not data.startswith(b'\x89PNG\r\n\x1A\n'):
                    return False
                    
                # Check for IEND chunk
                if b'IEND\xAE\x42\x60\x82' not in data:
                    return False
                    
                return True
        except Exception:
            return False
    
    def _validate_pdf(self, file_path: str) -> bool:
        """Validate PDF file format"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                # Check for PDF header
                if not data.startswith(b'%PDF-'):
                    return False
                    
                # Check for EOF marker
                if b'%%EOF' not in data:
                    return False
                    
                return True
        except Exception:
            return False
    
    def _validate_zip(self, file_path: str) -> bool:
        """Validate ZIP file format"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4)
                
                # Check for ZIP signature
                if data != b'PK\x03\x04':
                    return False
                    
                return True
        except Exception:
            return False
    
    def reconstruct_fragments(self, fragments: List[FileFragment], 
                            target_file_type: str = None) -> List[RecoveredFile]:
        """
        Reconstruct files from fragments
        
        Args:
            fragments: List of file fragments to reconstruct
            target_file_type: Optional file type to focus reconstruction on
            
        Returns:
            List of reconstructed files
        """
        logger.info(f"Starting fragment reconstruction for {len(fragments)} fragments")
        
        reconstructed_files = []
        
        try:
            # Group fragments by file type if specified
            if target_file_type:
                relevant_fragments = [f for f in fragments if f.signature_match == target_file_type]
            else:
                relevant_fragments = fragments
                
            # Sort fragments by offset
            sorted_fragments = sorted(relevant_fragments, key=lambda x: x.offset)
            
            # Identify contiguous fragments
            contiguous_groups = self._identify_contiguous_fragments(sorted_fragments)
            
            # Reconstruct each group
            for group in contiguous_groups:
                reconstructed_file = self._reconstruct_file_from_group(group)
                if reconstructed_file:
                    reconstructed_files.append(reconstructed_file)
                    
        except Exception as e:
            logger.error(f"Error during fragment reconstruction: {str(e)}")
            
        logger.info(f"Fragment reconstruction complete. Reconstructed {len(reconstructed_files)} files.")
        return reconstructed_files
    
    def _identify_contiguous_fragments(self, fragments: List[FileFragment]) -> List[List[FileFragment]]:
        """Group fragments that appear to be contiguous"""
        if not fragments:
            return []
            
        groups = []
        current_group = [fragments[0]]
        
        for i in range(1, len(fragments)):
            curr_frag = fragments[i]
            prev_frag = fragments[i-1]
            
            # Check if fragments are contiguous (with small tolerance)
            expected_offset = prev_frag.offset + len(prev_frag.data)
            if abs(curr_frag.offset - expected_offset) <= 10:  # 10 byte tolerance
                current_group.append(curr_frag)
            else:
                # Start a new group
                if len(current_group) > 0:
                    groups.append(current_group)
                current_group = [curr_frag]
                
        # Add the last group
        if current_group:
            groups.append(current_group)
            
        return groups
    
    def _reconstruct_file_from_group(self, fragments: List[FileFragment]) -> Optional[RecoveredFile]:
        """Reconstruct a file from a group of fragments"""
        if not fragments:
            return None
            
        try:
            # Determine file type and prepare a name
            first_frag = fragments[0]
            file_type = first_frag.signature_match or "unknown"
            extension = next((s.extension for s in self.COMMON_SIGNATURES if s.name == file_type), "bin")
            
            file_name = f"reconstructed_{file_type}_{first_frag.offset}.{extension}"
            file_path = os.path.join(self.output_dir, file_name)
            
            # Combine all fragment data
            combined_data = bytearray()
            fragment_offsets = []
            
            for fragment in fragments:
                combined_data.extend(fragment.data)
                fragment_offsets.append(fragment.offset)
                
            # Write the reconstructed file
            with open(file_path, 'wb') as f:
                f.write(combined_data)
                
            # Create the recovered file object
            checksum = hashlib.sha256(combined_data).hexdigest()
            recovered_file = RecoveredFile(
                file_path=file_path,
                file_type=file_type,
                original_offset=first_frag.offset,
                size=len(combined_data),
                fragments_used=fragment_offsets,
                validation_status={'initial_validation': 'pending'},
                checksum=checksum
            )
            
            # Validate the reconstruction
            self.validate_recovery(recovered_file)
            
            return recovered_file
            
        except Exception as e:
            logger.error(f"Error reconstructing file from fragments: {str(e)}")
            return None

# Example usage
if __name__ == "__main__":
    recovery_engine = FileRecoveryEngine(output_dir="recovered_files")
    
    # Example: Carve files from a disk image
    recovered_files = recovery_engine.carve_files("disk_image.dd")
    
    print(f"Recovered {len(recovered_files)} files")
    for file in recovered_files:
        validation_score = file.validation_status.get('score', 0)
        print(f"File: {file.file_path}, Type: {file.file_type}, " 
              f"Size: {file.size} bytes, Validation: {validation_score:.2f}")
