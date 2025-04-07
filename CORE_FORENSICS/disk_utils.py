# CORE_FORENSICS/disk_utils.py
import os
import glob
import subprocess
import logging
from typing import List, Optional, Dict

def detect_physical_disks() -> List[str]:
    """Find all physical disks with enhanced detection"""
    disks = []
    
    # Check standard disk devices
    disk_patterns = [
        '/dev/sd[a-z]',      # Standard SATA/SCSI
        '/dev/nvme*n1',       # NVMe devices
        '/dev/mmcblk*',       # SD cards/eMMC
        '/dev/vd[a-z]',       # Virtual disks
        '/dev/xvd[a-z]'       # Xen virtual disks
    ]
    
    for pattern in disk_patterns:
        disks.extend(dev for dev in glob.glob(pattern) if os.path.exists(dev))
    
    # Use lsblk for more reliable detection
    try:
        result = subprocess.run(
            ['lsblk', '-d', '-n', '-o', 'NAME'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in result.stdout.splitlines():
            if line.strip():
                disk_path = f"/dev/{line.strip()}"
                if disk_path not in disks and os.path.exists(disk_path):
                    disks.append(disk_path)
    except subprocess.CalledProcessError as e:
        logging.error(f"lsblk command failed: {e.stderr}")
    
    return sorted(set(disks))

def get_mount_point(device_path: str) -> Optional[str]:
    """Enhanced mount point detection with multiple methods"""
    try:
        # Method 1: Using findmnt (most reliable)
        result = subprocess.run(
            ['findmnt', '-n', '-o', 'TARGET', '--source', device_path],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stdout.strip():
            return result.stdout.strip()
        
        # Method 2: Using lsblk
        result = subprocess.run(
            ['lsblk', '-no', 'MOUNTPOINT', device_path],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stdout.strip():
            return result.stdout.strip()
        
        # Method 3: Checking /proc/mounts directly
        with open('/proc/mounts', 'r') as f:
            for line in f:
                if device_path in line:
                    return line.split()[1]
        
        return None
        
    except Exception as e:
        logging.error(f"Mount check failed for {device_path}: {str(e)}")
        return None

def unmount_disk(device_path: str) -> bool:
    """Enhanced unmount with multiple fallback methods"""
    unmount_commands = [
        ['umount', device_path],          # Standard unmount
        ['umount', '-l', device_path],     # Lazy unmount
        ['umount', '-f', device_path],     # Force unmount
        ['udisksctl', 'unmount', '-b', device_path]  # UDisks method
    ]
    
    for cmd in unmount_commands:
        try:
            result = subprocess.run(
                ['sudo'] + cmd,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Check for success conditions
            if result.returncode == 0:
                return True
            if "not mounted" in result.stderr.lower():
                return True
            if "not found" in result.stderr.lower():
                return False
                
        except Exception as e:
            logging.warning(f"Unmount attempt failed ({cmd}): {str(e)}")
            continue
    
    # Final check if really unmounted
    return get_mount_point(device_path) is None

def get_disk_info(device_path: str) -> Dict[str, str]:
    """Enhanced disk information gathering"""
    info = {
        'model': 'Unknown',
        'serial': 'Unknown',
        'size': 0,
        'type': 'Unknown',
        'readonly': False,
        'removable': False
    }
    
    try:
        # Get udev information
        udev_info = subprocess.run(
            ['udevadm', 'info', '--query=property', f'--name={device_path}'],
            check=True,
            stdout=subprocess.PIPE,
            text=True
        ).stdout
        
        for line in udev_info.splitlines():
            if line.startswith('ID_MODEL='):
                info['model'] = line.split('=', 1)[1]
            elif line.startswith('ID_SERIAL='):
                info['serial'] = line.split('=', 1)[1]
            elif line.startswith('ID_TYPE='):
                info['type'] = line.split('=', 1)[1]
            elif line.startswith('ID_DRIVE_FLASH_SD='):
                info['removable'] = True
            elif line.startswith('ID_CDROM='):
                info['type'] = 'CD/DVD'
        
        # Get size information
        size_bytes = subprocess.run(
            ['blockdev', '--getsize64', device_path],
            check=True,
            stdout=subprocess.PIPE,
            text=True
        ).stdout.strip()
        info['size'] = int(size_bytes) if size_bytes.isdigit() else 0
        
        # Check if read-only
        ro_status = subprocess.run(
            ['blockdev', '--getro', device_path],
            check=True,
            stdout=subprocess.PIPE,
            text=True
        ).stdout.strip()
        info['readonly'] = ro_status == '1'
        
        # Check if removable
        removable = subprocess.run(
            ['cat', f'/sys/block/{os.path.basename(device_path)}/removable'],
            check=False,
            stdout=subprocess.PIPE,
            text=True
        ).stdout.strip()
        info['removable'] = removable == '1' or info['removable']
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to get disk info for {device_path}: {e.stderr}")
    except Exception as e:
        logging.error(f"Unexpected error getting disk info: {str(e)}")
    
    return info
