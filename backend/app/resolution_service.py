import json
import os
import ipaddress
import logging

logger = logging.getLogger(__name__)

class IPResolver:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(IPResolver, cls).__new__(cls)
            # Initialize empty, load lazily
            cls._instance.mappings = {}
            cls._instance.subnets = {}
            cls._instance.loaded = False
        return cls._instance

    def load_config(self):
        """Load mapping configuration from JSON file"""
        print("DEBUG: IPResolver loading config...")
        try:
            # Try multiple possible paths to be robust against CWD differences
            base_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths = [
                os.path.join(base_dir, '..', 'config', 'network_map.json'),
                os.path.join(os.getcwd(), 'backend', 'config', 'network_map.json'),
                os.path.join(os.getcwd(), 'config', 'network_map.json'),
                '/home/sttp/pcap/backend/config/network_map.json' # Absolute fallback
            ]
            
            config_path = None
            for p in possible_paths:
                if os.path.exists(p):
                    config_path = p
                    break
            
            if config_path:
                print(f"DEBUG: Loading network map from {config_path}")
                logger.info(f"Loading network map from {config_path}")
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    self.mappings = data.get('mappings', {})
                    self.subnets = data.get('subnets', {})
                    print(f"DEBUG: Loaded {len(self.mappings)} mappings and {len(self.subnets)} subnets")
                    logger.info(f"Loaded {len(self.mappings)} mappings and {len(self.subnets)} subnets")
                    self.loaded = True
            else:
                print(f"DEBUG: Network map config not found. Checked: {possible_paths}")
                logger.warning(f"Network map config not found. Checked: {possible_paths}")
        except Exception as e:
            print(f"DEBUG: Failed to load network map: {e}")
            logger.error(f"Failed to load network map: {e}")

    def resolve(self, ip: str) -> str:
        """
        Resolve an IP address to a Network Function name.
        """
        if not self.loaded:
            self.load_config()

        if not ip:
            return "Unknown"

        if not ip:
            return "Unknown"
            
        # 1. Exact Match
        if ip in self.mappings:
            return self.mappings[ip]
            
        # 2. Subnet Match
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr, name in self.subnets.items():
                if ip_obj in ipaddress.ip_network(cidr):
                    # Append last octet for uniqueness if needed, or just return General Name
                    # For now returning generic name + octet to distinguish nodes
                    # e.g. "RAN_15"
                    last_octet = ip.split('.')[-1]
                    return f"{name}_{last_octet}"
        except ValueError:
            pass # Invalid IP
            
        return ip

# Global instance
resolver = IPResolver()
