import os
import mimetypes
from datetime import datetime
from pathlib import Path
import stat
import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

class FilesystemAnalyzer:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.timeline = []
        self.directory_structure = defaultdict(list)
        self.file_metadata = {}
        self.type_mismatches = []
        
        # Initialize mimetypes
        mimetypes.init()
        
        # Common file signatures (magic bytes) for file type validation
        self.file_signatures = {
            # Images
            b'\xFF\xD8\xFF': ('image/jpeg', ['jpg', 'jpeg']),
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ('image/png', ['png']),
            b'\x47\x49\x46\x38': ('image/gif', ['gif']),
            b'\x42\x4D': ('image/bmp', ['bmp']),
            # Documents
            b'\x25\x50\x44\x46': ('application/pdf', ['pdf']),
            b'\x50\x4B\x03\x04': ('application/zip', ['zip', 'docx', 'xlsx', 'pptx']),
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('application/msoffice', ['doc', 'xls', 'ppt']),
            # Executables
            b'\x4D\x5A': ('application/exe', ['exe', 'dll']),
            b'\x7F\x45\x4C\x46': ('application/elf', ['elf', 'so']),
            # Audio/Video
            b'\x49\x44\x33': ('audio/mp3', ['mp3']),
            b'\x66\x74\x79\x70': ('video/mp4', ['mp4', 'mov']),
            # Archives
            b'\x1F\x8B': ('application/gzip', ['gz', 'tgz']),
            b'\x42\x5A\x68': ('application/bzip2', ['bz2']),
            b'\x52\x61\x72\x21\x1A\x07': ('application/rar', ['rar']),
        }
        
    def parse_filesystem(self) -> Dict:
        """Parse the filesystem and collect metadata for all files and directories."""
        for entry in self.root_path.rglob('*'):
            try:
                stats = entry.stat()
                metadata = {
                    'path': str(entry),
                    'size': stats.st_size if entry.is_file() else 0,
                    'created': datetime.fromtimestamp(stats.st_ctime),
                    'modified': datetime.fromtimestamp(stats.st_mtime),
                    'accessed': datetime.fromtimestamp(stats.st_atime),
                    'type': 'file' if entry.is_file() else 'directory',
                    'permissions': stat.filemode(stats.st_mode),
                    'is_hidden': entry.name.startswith('.'),
                }
                
                if entry.is_file():
                    metadata['hash'] = self._calculate_file_hash(entry)
                    file_type_info = self._analyze_file_header(entry)
                    metadata.update(file_type_info)
                
                self.file_metadata[str(entry)] = metadata
                self._update_timeline(metadata)
                self._update_directory_structure(entry)
                
            except (PermissionError, FileNotFoundError) as e:
                print(f"Error processing {entry}: {str(e)}")
                
        return self.file_metadata
    
    def analyze_directory_structure(self) -> Dict:
        """Analyze directory structure and relationships."""
        analysis = {
            'total_files': len([x for x in self.file_metadata.values() if x['type'] == 'file']),
            'total_dirs': len([x for x in self.file_metadata.values() if x['type'] == 'directory']),
            'directory_contents': dict(self.directory_structure),
            'depth_analysis': self._analyze_directory_depth(),
            'size_distribution': self._analyze_size_distribution(),
            'file_type_mismatches': self.type_mismatches,
            'file_types_distribution': self._analyze_file_types_distribution()
        }
        return analysis
    
    def construct_timeline(self) -> List[Dict]:
        """Construct a sorted timeline of filesystem events."""
        return sorted(self.timeline, key=lambda x: x['timestamp'])
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError):
            return "Hash calculation failed"
    
    def _analyze_file_header(self, file_path: Path) -> Dict:
        """
        Analyze file header (magic bytes) to determine actual file type
        and detect mismatches with extension.
        """
        try:
            # Get file extension
            extension = file_path.suffix.lower().lstrip('.')
            
            # Read first 16 bytes for magic byte analysis
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Initialize result
            result = {
                'extension': extension,
                'claimed_type': mimetypes.guess_type(str(file_path))[0] or 'unknown',
                'actual_type': 'unknown',
                'magic_bytes': header[:8].hex(),
                'type_mismatch': False
            }
            
            # Check for known file signatures
            for signature, (mime_type, valid_extensions) in self.file_signatures.items():
                if header.startswith(signature):
                    result['actual_type'] = mime_type
                    
                    # Check for type mismatch
                    if extension and extension not in valid_extensions:
                        result['type_mismatch'] = True
                        mismatch_info = {
                            'path': str(file_path),
                            'extension': extension,
                            'claimed_type': result['claimed_type'],
                            'actual_type': mime_type,
                            'expected_extensions': valid_extensions
                        }
                        self.type_mismatches.append(mismatch_info)
                    
                    break
            
            return result
            
        except (PermissionError, FileNotFoundError):
            return {
                'extension': extension if 'extension' in locals() else '',
                'claimed_type': mimetypes.guess_type(str(file_path))[0] or 'unknown',
                'actual_type': 'unknown',
                'magic_bytes': '',
                'type_mismatch': False
            }
    
    def _update_timeline(self, metadata: Dict) -> None:
        """Update timeline with file/directory events."""
        for event_type, timestamp in [
            ('created', metadata['created']),
            ('modified', metadata['modified']),
            ('accessed', metadata['accessed'])
        ]:
            self.timeline.append({
                'timestamp': timestamp,
                'event_type': event_type,
                'path': metadata['path'],
                'item_type': metadata['type']
            })
    
    def _update_directory_structure(self, entry: Path) -> None:
        """Update directory structure mapping."""
        parent = str(entry.parent)
        self.directory_structure[parent].append({
            'name': entry.name,
            'type': 'file' if entry.is_file() else 'directory'
        })
    
    def _analyze_directory_depth(self) -> Dict[int, int]:
        """Analyze directory depth distribution."""
        depth_distribution = defaultdict(int)
        for path in self.file_metadata:
            depth = len(Path(path).relative_to(self.root_path).parts)
            depth_distribution[depth] += 1
        return dict(depth_distribution)
    
    def _analyze_size_distribution(self) -> Dict[str, int]:
        """Analyze file size distribution."""
        size_ranges = {
            '0-1KB': 0,
            '1KB-1MB': 0,
            '1MB-100MB': 0,
            '100MB+': 0
        }
        
        for metadata in self.file_metadata.values():
            if metadata['type'] == 'file':
                size = metadata['size']
                if size <= 1024:
                    size_ranges['0-1KB'] += 1
                elif size <= 1024 * 1024:
                    size_ranges['1KB-1MB'] += 1
                elif size <= 100 * 1024 * 1024:
                    size_ranges['1MB-100MB'] += 1
                else:
                    size_ranges['100MB+'] += 1
        
        return size_ranges
    
    def _analyze_file_types_distribution(self) -> Dict[str, int]:
        """Analyze distribution of file types based on magic bytes analysis."""
        type_distribution = defaultdict(int)
        
        for metadata in self.file_metadata.values():
            if metadata['type'] == 'file' and 'actual_type' in metadata:
                type_distribution[metadata['actual_type']] += 1
        
        return dict(type_distribution)
    
    def get_type_mismatches(self) -> List[Dict]:
        """Return a list of files with type mismatches."""
        return self.type_mismatches
    
    def analyze_file_headers(self, file_path: Optional[str] = None) -> Dict:
        """
        Analyze file headers for a specific file or all files.
        
        :param file_path: Optional path to a specific file to analyze
        :return: Dictionary with analysis results
        """
        if file_path:
            path = Path(file_path)
            if path.is_file() and path.exists():
                return self._analyze_file_header(path)
            else:
                return {"error": "File not found or not a regular file"}
        
        # Analyze all files
        results = {
            'total_files_analyzed': 0,
            'identified_types': 0,
            'unknown_types': 0,
            'type_mismatches': len(self.type_mismatches),
            'type_distribution': self._analyze_file_types_distribution()
        }
        
        for metadata in self.file_metadata.values():
            if metadata['type'] == 'file':
                results['total_files_analyzed'] += 1
                if metadata.get('actual_type', 'unknown') != 'unknown':
                    results['identified_types'] += 1
                else:
                    results['unknown_types'] += 1
        
        return results
