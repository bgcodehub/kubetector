import yaml
from colorama import init, Fore, Style
import os
import sys
from typing import Dict, List, Any
import re

# Initialize colorama for colored output
init()

class ResourceValue:
    """Helper class to parse and compare resource values (e.g., '256Mi', '500m')"""
    def __init__(self, value: str):
        self.value = value
        self.numeric, self.unit = self._parse_value()

    def _parse_value(self):
        if not self.value:
            return 0, ""
        match = re.match(r"(\d+(?:\.\d+)?)([a-zA-Z]+)?", str(self.value))
        if not match:
            return 0, ""
        num, unit = match.groups()
        return float(num), unit or ""

    def __lt__(self, other):
        if not isinstance(other, ResourceValue):
            other = ResourceValue(other)
        if self.unit != other.unit:
            return False  # Can't compare different units without conversion
        return self.numeric < other.numeric

    def __gt__(self, other):
        if not isinstance(other, ResourceValue):
            other = ResourceValue(other)
        if self.unit != other.unit:
            return False
        return self.numeric > other.numeric

class K8sValidator:
    def __init__(self, config_path: str, manifest_dir: str = None):
        self.rules = self.load_rules(config_path)
        self.warnings = []
        self.errors = []
        self.all_manifests = self.load_all_manifests(manifest_dir) if manifest_dir else []

    def load_rules(self, config_path: str) -> Dict:
        """Load validation rules from config file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"{Fore.RED}Error loading config: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def load_all_manifests(self, manifest_dir: str) -> List[Dict]:
        """Load all manifests from a directory for cross-referencing"""
        manifests = []
        for root, _, files in os.walk(manifest_dir):
            for file in files:
                if file.endswith(('.yaml', '.yml')):
                    with open(os.path.join(root, file), 'r') as f:
                        manifests.extend([m for m in yaml.safe_load_all(f) if m])
        return manifests

    def validate_manifest(self, manifest_path: str):
        """Validate a single manifest file"""
        try:
            with open(manifest_path, 'r') as f:
                manifests = list(yaml.safe_load_all(f))
                
            print(f"\n{Fore.CYAN}Validating: {manifest_path}{Style.RESET_ALL}")
            for manifest in manifests:
                if manifest:
                    self.check_manifest(manifest)
                    
            self.print_results()
            self.warnings.clear()
            self.errors.clear()
            
        except Exception as e:
            print(f"{Fore.RED}Error reading manifest: {e}{Style.RESET_ALL}")

    def check_manifest(self, manifest: Dict):
        """Check individual manifest against all rules"""
        kind = manifest.get('kind', '').lower()
        
        self.check_required_fields(manifest, kind)
        self.check_namespace(manifest)
        self.check_labels_annotations(manifest)
        self.check_resource_limits(manifest, kind)
        self.check_security_context(manifest, kind)
        self.check_service_relationship(manifest, kind)
        self.check_image_policies(manifest, kind)
        self.check_networking(manifest, kind)
        self.check_probes(manifest, kind)
        self.check_volumes(manifest, kind)

    def get_nested_value(self, obj: Dict, path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = path.split('.')
        value = obj
        for key in keys:
            value = value.get(key, {}) if isinstance(value, dict) else {}
        return value if value != {} else None

    def check_required_fields(self, manifest: Dict, kind: str):
        """Check for required fields based on kind"""
        required_fields = self.rules.get('required_fields', {}).get(kind, [])
        for field in required_fields:
            if '.' in field:
                if not self.get_nested_value(manifest, field):
                    self.errors.append(f"Missing required field: {field}")
            elif field not in manifest:
                self.errors.append(f"Missing required field: {field}")

    def check_namespace(self, manifest: Dict):
        """Check namespace requirements"""
        ns_rules = self.rules.get('namespace', {})
        actual_ns = manifest.get('metadata', {}).get('namespace', 'default')
        
        if ns_rules.get('required') and not actual_ns:
            self.errors.append("Namespace is required but not specified")
        if ns_rules.get('allowed') and actual_ns not in ns_rules['allowed']:
            self.errors.append(f"Namespace '{actual_ns}' not in allowed list: {ns_rules['allowed']}")

    def check_labels_annotations(self, manifest: Dict):
        """Check required labels and annotations"""
        metadata = manifest.get('metadata', {})
        
        for key, rules in self.rules.get('labels', {}).items():
            actual = metadata.get('labels', {}).get(key)
            if rules.get('required') and actual is None:
                self.warnings.append(f"Required label '{key}' missing")
            if rules.get('value') and actual != rules['value']:
                self.warnings.append(f"Label '{key}' must be '{rules['value']}', got '{actual}'")

        for key, rules in self.rules.get('annotations', {}).items():
            actual = metadata.get('annotations', {}).get(key)
            if rules.get('required') and actual is None:
                self.warnings.append(f"Required annotation '{key}' missing")
            if rules.get('value') and actual != rules['value']:
                self.warnings.append(f"Annotation '{key}' must be '{rules['value']}', got '{actual}'")

    def check_resource_limits(self, manifest: Dict, kind: str):
        """Check resource requests and limits"""
        if kind in ['deployment', 'pod']:
            containers = manifest.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
            rules = self.rules.get('resources', {})
            
            for container in containers:
                name = container.get('name', 'unnamed')
                requests = container.get('resources', {}).get('requests', {})
                limits = container.get('resources', {}).get('limits', {})
                
                for res, rule in rules.get('requests', {}).items():
                    actual = ResourceValue(requests.get(res, "0"))
                    if rule.get('min') and actual < ResourceValue(rule['min']):
                        self.warnings.append(f"Container '{name}' {res} request '{actual.value}' below min '{rule['min']}'")
                    if rule.get('required') and not requests.get(res):
                        self.warnings.append(f"Container '{name}' missing {res} request")
                
                for res, rule in rules.get('limits', {}).items():
                    actual = ResourceValue(limits.get(res, "0"))
                    if rule.get('max') and actual > ResourceValue(rule['max']):
                        self.warnings.append(f"Container '{name}' {res} limit '{actual.value}' above max '{rule['max']}'")
                    if rule.get('required') and not limits.get(res):
                        self.warnings.append(f"Container '{name}' missing {res} limit")

    def check_security_context(self, manifest: Dict, kind: str):
        """Check pod and container security contexts"""
        if kind in ['deployment', 'pod']:
            pod_spec = manifest.get('spec', {}).get('template', {}).get('spec', {})
            containers = pod_spec.get('containers', [])
            rules = self.rules.get('security', {})
            
            # Pod-level security context
            pod_sc = pod_spec.get('securityContext', {})
            for key, rule in rules.get('pod', {}).items():
                actual = pod_sc.get(key)
                if rule.get('required') and actual is None:
                    self.errors.append(f"Pod securityContext.{key} is required")
                if rule.get('value') is not None and actual != rule['value']:
                    self.errors.append(f"Pod securityContext.{key} must be {rule['value']}, got {actual}")
            
            # Container-level security context
            for container in containers:
                name = container.get('name', 'unnamed')
                cont_sc = container.get('securityContext', {})
                for key, rule in rules.get('container', {}).items():
                    actual = cont_sc.get(key)
                    if rule.get('required') and actual is None:
                        self.errors.append(f"Container '{name}' securityContext.{key} is required")
                    if rule.get('value') is not None and actual != rule['value']:
                        self.errors.append(f"Container '{name}' securityContext.{key} must be {rule['value']}, got {actual}")

    def check_service_relationship(self, manifest: Dict, kind: str):
        """Check if deployment has a corresponding service"""
        if kind == 'deployment' and self.rules.get('require_service', False):
            labels = manifest.get('spec', {}).get('selector', {}).get('matchLabels', {})
            service_found = False
            for other in self.all_manifests:
                if other.get('kind', '').lower() == 'service':
                    svc_selector = other.get('spec', {}).get('selector', {})
                    if svc_selector == labels:
                        service_found = True
                        break
            if not service_found:
                self.warnings.append("Deployment missing corresponding Service with matching selector")

    def check_image_policies(self, manifest: Dict, kind: str):
        """Check container image policies"""
        if kind in ['deployment', 'pod']:
            containers = manifest.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
            rules = self.rules.get('images', {})
            
            for container in containers:
                name = container.get('name', 'unnamed')
                image = container.get('image', '')
                
                if rules.get('registry') and not image.startswith(rules['registry']):
                    self.errors.append(f"Container '{name}' image '{image}' must use registry '{rules['registry']}'")
                if rules.get('no_latest') and ':latest' in image:
                    self.warnings.append(f"Container '{name}' image '{image}' uses 'latest' tag")
                if rules.get('allowed') and image not in rules['allowed']:
                    self.errors.append(f"Container '{name}' image '{image}' not in allowed list")

    def check_networking(self, manifest: Dict, kind: str):
        """Check networking configurations"""
        rules = self.rules.get('networking', {})
        
        if kind in ['deployment', 'pod']:
            containers = manifest.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
            for container in containers:
                name = container.get('name', 'unnamed')
                ports = container.get('ports', [])
                
                if rules.get('ports_required') and not ports:
                    self.warnings.append(f"Container '{name}' missing port definitions")
                for port in ports:
                    if rules.get('allowed_ports') and port.get('containerPort') not in rules['allowed_ports']:
                        self.warnings.append(f"Container '{name}' port {port.get('containerPort')} not in allowed list")

    def check_probes(self, manifest: Dict, kind: str):
        """Check liveness and readiness probes"""
        if kind in ['deployment', 'pod']:
            containers = manifest.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
            rules = self.rules.get('probes', {})
            
            for container in containers:
                name = container.get('name', 'unnamed')
                liveness = container.get('livenessProbe')
                readiness = container.get('readinessProbe')
                
                if rules.get('liveness_required') and not liveness:
                    self.warnings.append(f"Container '{name}' missing liveness probe")
                if rules.get('readiness_required') and not readiness:
                    self.warnings.append(f"Container '{name}' missing readiness probe")

    def check_volumes(self, manifest: Dict, kind: str):
        """Check volume configurations"""
        if kind in ['deployment', 'pod']:
            spec = manifest.get('spec', {}).get('template', {}).get('spec', {})
            volumes = spec.get('volumes', [])
            rules = self.rules.get('volumes', {})
            
            if rules.get('required') and not volumes:
                self.warnings.append("Volumes are required but none defined")
            for volume in volumes:
                name = volume.get('name', 'unnamed')
                if rules.get('allowed_types'):
                    vol_type = next((k for k in volume.keys() if k != 'name'), None)
                    if vol_type not in rules['allowed_types']:
                        self.warnings.append(f"Volume '{name}' type '{vol_type}' not in allowed types")

    def print_results(self):
        """Print validation results with colors"""
        if self.errors:
            print(f"{Fore.RED}Errors found:{Style.RESET_ALL}")
            for error in self.errors:
                print(f"{Fore.RED}✗ {error}{Style.RESET_ALL}")
                
        if self.warnings:
            print(f"{Fore.YELLOW}Warnings:{Style.RESET_ALL}")
            for warning in self.warnings:
                print(f"{Fore.YELLOW}⚠ {warning}{Style.RESET_ALL}")
                
        if not self.errors and not self.warnings:
            print(f"{Fore.GREEN}✓ Manifest looks good!{Style.RESET_ALL}")

def main():
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python k8s_validator.py <manifest_path> [<manifest_dir>]{Style.RESET_ALL}")
        sys.exit(1)

    manifest_path = sys.argv[1]
    manifest_dir = sys.argv[2] if len(sys.argv) > 2 else None
    validator = K8sValidator('validation_rules.yaml', manifest_dir)
    validator.validate_manifest(manifest_path)

if __name__ == "__main__":
    main()