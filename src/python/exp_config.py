

import os
import yaml
from common import *

class ExperimentConfig:
    """Configuration class for eNetSTL experiments."""

    def __init__(self, config_file=None):
        """Initialize configuration from YAML file or create with defaults."""
        if config_file is None:
            config_file = os.path.join(PROJECT_ROOT_DIR, "configs", "exp_config.yaml")

        self.config_file = config_file
        self._config = self._load_or_create_config()
        self._setup_log_directories()

    def _load_or_create_config(self):
        """Load existing config or create with default values."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                print(f"Error loading config file {self.config_file}: {e}")
                print("Using default configuration.")

        # Create default configuration if file doesn't exist or is invalid
        default_log_path = os.path.join(PROJECT_ROOT_DIR, "log")
        default_log_pps = os.path.join(default_log_path, "pps")
        default_log_latency_no_load = os.path.join(default_log_path, "latency_no_load")
        default_log_latency_high_load = os.path.join(default_log_path, "latency_high_load")
        default_config = {
            'interface': {
                'name': 'ens2f0np0'
            },
            'experiment': {
                'repeat_count': 5,
                'print_quiet': False,
                'latency_testing': {
                    'lat_pps': '1000',
                    'bg_no_pps': '0',
                    'bg_high_pps': '20000000'
                }
            },
            'trex': {
                'server': '223.3.71.41',
                'traffic_profile_file': 'stream_generator.py',
                'latency_test_port': 0,
                'latency_test_ports': [0]
            },
            'logging': {
                'pps_log_path': default_log_pps,
                'latency_no_load_path': default_log_latency_no_load,
                'latency_high_load_path': default_log_latency_high_load
            }
        }

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

        # Save default config to file
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2)
            print(f"Created default configuration file: {self.config_file}")
        except Exception as e:
            print(f"Error creating config file {self.config_file}: {e}")

        return default_config

    def _setup_log_directories(self):
        """Create log directories if they don't exist."""
        log_paths = [
            self.pps_log_path,
            self.latency_no_load_path,
            self.latency_high_load_path
        ]

        for path in log_paths:
            if not os.path.exists(path):
                os.makedirs(path)

    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving config file {self.config_file}: {e}")

    @property
    def interface_name(self):
        return self._config['interface']['name']

    @interface_name.setter
    def interface_name(self, value):
        self._config['interface']['name'] = value

    @property
    def exp_repeat_count(self):
        return self._config['experiment']['repeat_count']

    @exp_repeat_count.setter
    def exp_repeat_count(self, value):
        self._config['experiment']['repeat_count'] = value

    @property
    def print_quiet(self):
        return self._config['experiment']['print_quiet']

    @print_quiet.setter
    def print_quiet(self, value):
        self._config['experiment']['print_quiet'] = value

    # Latency testing configuration properties
    @property
    def lat_pps(self):
        return self._config['experiment']['latency_testing']['lat_pps']

    @lat_pps.setter
    def lat_pps(self, value):
        self._config['experiment']['latency_testing']['lat_pps'] = str(value)

    @property
    def bg_no_pps(self):
        return self._config['experiment']['latency_testing']['bg_no_pps']

    @bg_no_pps.setter
    def bg_no_pps(self, value):
        self._config['experiment']['latency_testing']['bg_no_pps'] = str(value)

    @property
    def bg_high_pps(self):
        return self._config['experiment']['latency_testing']['bg_high_pps']

    @bg_high_pps.setter
    def bg_high_pps(self, value):
        self._config['experiment']['latency_testing']['bg_high_pps'] = str(value)

    @property
    def trex_server(self):
        return self._config['trex']['server']

    @trex_server.setter
    def trex_server(self, value):
        self._config['trex']['server'] = value

    @property
    def traffic_profile_file(self):
        return os.path.join(os.path.dirname(__file__), self._config['trex']['traffic_profile_file'])

    @traffic_profile_file.setter
    def traffic_profile_file(self, value):
        self._config['trex']['traffic_profile_file'] = value

    @property
    def latency_test_port(self):
        return self._config['trex']['latency_test_port']

    @latency_test_port.setter
    def latency_test_port(self, value):
        self._config['trex']['latency_test_port'] = value

    @property
    def latency_test_ports(self):
        return self._config['trex']['latency_test_ports']

    @latency_test_ports.setter
    def latency_test_ports(self, value):
        self._config['trex']['latency_test_ports'] = value

    @property
    def pps_log_path(self):
        return os.path.normpath(os.path.join(PROJECT_ROOT_DIR, self._config['logging']['pps_log_path']))

    @property
    def latency_no_load_path(self):
        return os.path.normpath(os.path.join(PROJECT_ROOT_DIR, self._config['logging']['latency_no_load_path']))

    @property
    def latency_high_load_path(self):
        return os.path.normpath(os.path.join(PROJECT_ROOT_DIR, self._config['logging']['latency_high_load_path']))

    def get_config_dict(self):
        """Return the full configuration dictionary."""
        return self._config.copy()

    def update_config(self, config_dict):
        """Update configuration with new values."""
        self._config.update(config_dict)
        self._setup_log_directories()

# Global configuration instance
config = ExperimentConfig()

# Backward compatibility - expose variables as before
interface_name = config.interface_name
exp_repeat_count = config.exp_repeat_count
TREX_SERVER = config.trex_server
TRAFFIC_PRIFILE_FILE = config.traffic_profile_file
LAT_TEST_PORT = config.latency_test_port
LAT_TEST_PORTS = config.latency_test_ports
PRINT_QUIET = config.print_quiet

# Log paths
PPS_LOG_PATH = config.pps_log_path
LAT_NO_LOG_PATH = config.latency_no_load_path
LAT_HIGH_LOG_PATH = config.latency_high_load_path


if __name__ == "__main__":
    # For testing purposes
    print("Experiment Configuration:")
    print(yaml.dump(config.get_config_dict(), default_flow_style=False, indent=2))