import os
from datetime import datetime
from pathlib import Path
import stat
import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple

class FilesystemAnalyzer:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.timeline = []
        self.directory_structure = defaultdict(list)
        self.file_metadata = {}
        
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
            'size_distribution': self._analyze_size_distribution()
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
