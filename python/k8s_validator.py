import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
import os
import sys
from typing import Dict, List, Any
import re

console = Console()


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
        self.all_manifests = (
            self.load_all_manifests(manifest_dir) if manifest_dir else []
        )

    def load_rules(self, config_path: str) -> Dict:
        """Load validation rules from config file"""
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            sys.exit(1)

    def load_all_manifests(self, manifest_dir: str) -> List[Dict]:
        """Load all manifests from a directory for cross-referencing"""
        manifests = []
        for root, _, files in os.walk(manifest_dir):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    with open(os.path.join(root, file), "r") as f:
                        manifests.extend([m for m in yaml.safe_load_all(f) if m])
        return manifests

    def validate_manifest(self, manifest_path: str):
        """Validate a single manifest file"""
        try:
            with open(manifest_path, "r") as f:
                manifests = list(yaml.safe_load_all(f))

            console.print(
                Panel(f"Validating: {manifest_path}", style="cyan", border_style="cyan")
            )
            for manifest in manifests:
                if manifest:
                    self.check_manifest(manifest)

            self.print_results()
            self.warnings.clear()
            self.errors.clear()

        except Exception as e:
            console.print(f"[red]Error reading manifest: {e}[/red]")

    def check_manifest(self, manifest: Dict):
        """Check individual manifest against all rules"""
        kind = manifest.get("kind", "").lower()

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
        keys = path.split(".")
        value = obj
        for key in keys:
            value = value.get(key, {}) if isinstance(value, dict) else {}
        return value if value != {} else None

    def check_required_fields(self, manifest: Dict, kind: str):
        """Check for required fields based on kind"""
        required_fields = self.rules.get("required_fields", {}).get(kind, [])
        for field in required_fields:
            if "." in field:
                if not self.get_nested_value(manifest, field):
                    self.errors.append(
                        {
                            "message": f"Missing required field: {field}",
                            "reason": f"The field '{field}' is required for {kind} resources to ensure proper configuration.",
                            "fix": f"{field.split('.')[0]}:\n  # Add the required field '{field}'",
                        }
                    )
            elif field not in manifest:
                self.errors.append(
                    {
                        "message": f"Missing required field: {field}",
                        "reason": f"The field '{field}' is required for {kind} resources to ensure proper configuration.",
                        "fix": f"{field}: <value>\n  # Add the required field '{field}'",
                    }
                )

    def check_namespace(self, manifest: Dict):
        """Check namespace requirements"""
        ns_rules = self.rules.get("namespace", {})
        actual_ns = manifest.get("metadata", {}).get("namespace", "default")

        if ns_rules.get("required") and not manifest.get("metadata", {}).get(
            "namespace"
        ):
            self.errors.append(
                {
                    "message": "Namespace is required but not specified",
                    "reason": "A namespace must be explicitly specified to ensure resources are deployed in the correct environment.",
                    "fix": "metadata:\n  namespace: <your-app-namespace>  # Specify your app's namespace",
                }
            )
        if actual_ns == "default":
            self.errors.append(
                {
                    "message": "Namespace cannot be 'default'",
                    "reason": "Using the 'default' namespace is not allowed; specify a custom namespace for your app.",
                    "fix": "metadata:\n  namespace: <your-app-namespace>  # Replace 'default' with your app's namespace",
                }
            )

    def check_labels_annotations(self, manifest: Dict):
        """Check required labels and annotations"""
        metadata = manifest.get("metadata", {})

        for key, rules in self.rules.get("labels", {}).items():
            actual = metadata.get("labels", {}).get(key)
            if rules.get("required") and actual is None:
                self.warnings.append(
                    {
                        "message": f"Required label '{key}' missing",
                        "reason": f"The label '{key}' is required for organizational consistency and resource identification.",
                        "fix": f"metadata:\n  labels:\n    {key}: <value>  # Add the required label",
                    }
                )
            if rules.get("value") and actual != rules["value"]:
                self.warnings.append(
                    {
                        "message": f"Label '{key}' must be '{rules['value']}', got '{actual}'",
                        "reason": f"The label '{key}' must have the value '{rules['value']}' to meet organizational standards.",
                        "fix": f"metadata:\n  labels:\n    {key}: {rules['value']}  # Set the correct value",
                    }
                )

        for key, rules in self.rules.get("annotations", {}).items():
            actual = metadata.get("annotations", {}).get(key)
            if rules.get("required") and actual is None:
                self.warnings.append(
                    {
                        "message": f"Required annotation '{key}' missing",
                        "reason": f"The annotation '{key}' is required for metadata tracking and monitoring.",
                        "fix": f"metadata:\n  annotations:\n    {key}: <value>  # Add the required annotation",
                    }
                )
            if rules.get("value") and actual != rules["value"]:
                self.warnings.append(
                    {
                        "message": f"Annotation '{key}' must be '{rules['value']}', got '{actual}'",
                        "reason": f"The annotation '{key}' must have the value '{rules['value']}' to meet organizational standards.",
                        "fix": f"metadata:\n  annotations:\n    {key}: {rules['value']}  # Set the correct value",
                    }
                )

    def check_resource_limits(self, manifest: Dict, kind: str):
        """Check resource requests and limits"""
        if kind in ["deployment", "pod"]:
            containers = (
                manifest.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", [])
            )
            rules = self.rules.get("resources", {})

            for container in containers:
                name = container.get("name", "unnamed")
                requests = container.get("resources", {}).get("requests", {})
                limits = container.get("resources", {}).get("limits", {})

                for res, rule in rules.get("requests", {}).items():
                    actual = ResourceValue(requests.get(res, "0"))
                    if rule.get("min") and actual < ResourceValue(rule["min"]):
                        self.warnings.append(
                            {
                                "message": f"Container '{name}' {res} request '{actual.value}' below min '{rule['min']}'",
                                "reason": f"Resource requests for '{res}' must be at least '{rule['min']}' to ensure adequate resource allocation.",
                                "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        resources:\n          requests:\n            {res}: {rule['min']}  # Increase to at least the minimum",
                            }
                        )
                    if rule.get("required") and not requests.get(res):
                        self.warnings.append(
                            {
                                "message": f"Container '{name}' missing {res} request",
                                "reason": f"A '{res}' request is required to ensure the container has guaranteed resources.",
                                "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        resources:\n          requests:\n            {res}: <value>  # Add the required request",
                            }
                        )

                for res, rule in rules.get("limits", {}).items():
                    actual = ResourceValue(limits.get(res, "0"))
                    if rule.get("max") and actual > ResourceValue(rule["max"]):
                        self.warnings.append(
                            {
                                "message": f"Container '{name}' {res} limit '{actual.value}' above max '{rule['max']}'",
                                "reason": f"Resource limits for '{res}' must not exceed '{rule['max']}' to prevent over-allocation.",
                                "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        resources:\n          limits:\n            {res}: {rule['max']}  # Decrease to at most the maximum",
                            }
                        )
                    if rule.get("required") and not limits.get(res):
                        self.warnings.append(
                            {
                                "message": f"Container '{name}' missing {res} limit",
                                "reason": f"A '{res}' limit is required to prevent resource over-usage.",
                                "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        resources:\n          limits:\n            {res}: <value>  # Add the required limit",
                            }
                        )

    def check_security_context(self, manifest: Dict, kind: str):
        """Check pod and container security contexts"""
        if kind in ["deployment", "pod"]:
            pod_spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
            containers = pod_spec.get("containers", [])
            rules = self.rules.get("security", {})

            # Pod-level security context
            pod_sc = pod_spec.get("securityContext", {})
            for key, rule in rules.get("pod", {}).items():
                actual = pod_sc.get(key)
                if rule.get("required") and actual is None:
                    self.errors.append(
                        {
                            "message": f"Pod securityContext.{key} is required",
                            "reason": f"The pod-level security context setting '{key}' is required for security compliance.",
                            "fix": f"spec:\n  template:\n    spec:\n      securityContext:\n        {key}: <value>  # Add the required setting",
                        }
                    )
                if rule.get("value") is not None and actual != rule["value"]:
                    self.errors.append(
                        {
                            "message": f"Pod securityContext.{key} must be {rule['value']}, got {actual}",
                            "reason": f"The pod-level security context setting '{key}' must be {rule['value']} for security compliance.",
                            "fix": f"spec:\n  template:\n    spec:\n      securityContext:\n        {key}: {rule['value']}  # Set the correct value",
                        }
                    )

            # Container-level security context
            for container in containers:
                name = container.get("name", "unnamed")
                cont_sc = container.get("securityContext", {})
                for key, rule in rules.get("container", {}).items():
                    actual = cont_sc.get(key)
                    if rule.get("required") and actual is None:
                        self.errors.append(
                            {
                                "message": f"Container '{name}' securityContext.{key} is required",
                                "reason": f"The container-level security context setting '{key}' is required for security compliance.",
                                "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        securityContext:\n          {key}: <value>  # Add the required setting",
                            }
                        )
                    if rule.get("value") is not None and actual != rule["value"]:
                        self.errors.append(
                            {
                                "message": f"Container '{name}' securityContext.{key} must be {rule['value']}, got {actual}",
                                "reason": f"The container-level security context setting '{key}' must be {rule['value']} for security compliance.",
                                "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        securityContext:\n          {key}: {rule['value']}  # Set the correct value",
                            }
                        )

    def check_service_relationship(self, manifest: Dict, kind: str):
        """Check if deployment has a corresponding service"""
        if kind == "deployment" and self.rules.get("require_service", False):
            labels = manifest.get("spec", {}).get("selector", {}).get("matchLabels", {})
            service_found = False
            for other in self.all_manifests:
                if other.get("kind", "").lower() == "service":
                    svc_selector = other.get("spec", {}).get("selector", {})
                    if svc_selector == labels:
                        service_found = True
                        break
            if not service_found:
                self.warnings.append(
                    {
                        "message": "Deployment missing corresponding Service with matching selector",
                        "reason": "A Service is required to expose the Deployment's pods to the network.",
                        "fix": f"apiVersion: v1\nkind: Service\nmetadata:\n  name: <service-name>\nspec:\n  selector:\n    {yaml.dump(labels).strip()}\n  ports:\n  - protocol: TCP\n    port: 80\n    targetPort: 80  # Create a Service with matching selector",
                    }
                )

    def check_image_policies(self, manifest: Dict, kind: str):
        """Check container image policies"""
        if kind in ["deployment", "pod"]:
            containers = (
                manifest.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", [])
            )
            rules = self.rules.get("images", {})

            for container in containers:
                name = container.get("name", "unnamed")
                image = container.get("image", "")

                if rules.get("registry") and not image.startswith(rules["registry"]):
                    self.errors.append(
                        {
                            "message": f"Container '{name}' image '{image}' must use registry '{rules['registry']}'",
                            "reason": f"All images must come from the approved registry '{rules['registry']}' for security and compliance.",
                            "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        image: {rules['registry']}<image-name>:<tag>  # Use the approved registry",
                        }
                    )
                if rules.get("no_latest") and ":latest" in image:
                    self.warnings.append(
                        {
                            "message": f"Container '{name}' image '{image}' uses 'latest' tag",
                            "reason": "Using the 'latest' tag can lead to unpredictable deployments; specify a specific version.",
                            "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        image: {image.replace(':latest', ':<specific-version>')}  # Replace 'latest' with a specific version",
                        }
                    )
                if rules.get("allowed") and image not in rules["allowed"]:
                    self.errors.append(
                        {
                            "message": f"Container '{name}' image '{image}' not in allowed list",
                            "reason": f"Only approved images are allowed: {rules['allowed']}.",
                            "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        image: {rules['allowed'][0]}  # Use an approved image",
                        }
                    )

    def check_networking(self, manifest: Dict, kind: str):
        """Check networking configurations"""
        rules = self.rules.get("networking", {})

        if kind in ["deployment", "pod"]:
            containers = (
                manifest.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", [])
            )
            for container in containers:
                name = container.get("name", "unnamed")
                ports = container.get("ports", [])

                if rules.get("ports_required") and not ports:
                    self.warnings.append(
                        {
                            "message": f"Container '{name}' missing port definitions",
                            "reason": "Port definitions are required to expose the container to the network.",
                            "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        ports:\n        - containerPort: 80  # Add port definitions",
                        }
                    )
                for port in ports:
                    if (
                        rules.get("allowed_ports")
                        and port.get("containerPort") not in rules["allowed_ports"]
                    ):
                        self.warnings.append(
                            {
                                "message": f"Container '{name}' port {port.get('containerPort')} not in allowed list",
                                "reason": f"Only ports {rules['allowed_ports']} are allowed for security and consistency.",
                                "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        ports:\n        - containerPort: {rules['allowed_ports'][0]}  # Use an allowed port",
                            }
                        )

    def check_probes(self, manifest: Dict, kind: str):
        """Check liveness and readiness probes"""
        if kind in ["deployment", "pod"]:
            containers = (
                manifest.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", [])
            )
            rules = self.rules.get("probes", {})

            for container in containers:
                name = container.get("name", "unnamed")
                liveness = container.get("livenessProbe")
                readiness = container.get("readinessProbe")

                if rules.get("liveness_required") and not liveness:
                    self.warnings.append(
                        {
                            "message": f"Container '{name}' missing liveness probe",
                            "reason": "A liveness probe is required to ensure the container is running correctly.",
                            "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        livenessProbe:\n          httpGet:\n            path: /health\n            port: 80\n          initialDelaySeconds: 15\n          periodSeconds: 10  # Add a liveness probe",
                        }
                    )
                if rules.get("readiness_required") and not readiness:
                    self.warnings.append(
                        {
                            "message": f"Container '{name}' missing readiness probe",
                            "reason": "A readiness probe is required to ensure the container is ready to serve traffic.",
                            "fix": f"spec:\n  template:\n    spec:\n      containers:\n      - name: {name}\n        readinessProbe:\n          httpGet:\n            path: /ready\n            port: 80\n          initialDelaySeconds: 5\n          periodSeconds: 10  # Add a readiness probe",
                        }
                    )

    def check_volumes(self, manifest: Dict, kind: str):
        """Check volume configurations"""
        if kind in ["deployment", "pod"]:
            spec = manifest.get("spec", {}).get("template", {}).get("spec", {})
            volumes = spec.get("volumes", [])
            rules = self.rules.get("volumes", {})

            if rules.get("required") and not volumes:
                self.warnings.append(
                    {
                        "message": "Volumes are required but none defined",
                        "reason": "Volumes are required for persistent storage or configuration.",
                        "fix": f"spec:\n  template:\n    spec:\n      volumes:\n      - name: <volume-name>\n        configMap:\n          name: <configmap-name>  # Add a volume",
                    }
                )
            for volume in volumes:
                name = volume.get("name", "unnamed")
                if rules.get("allowed_types"):
                    vol_type = next((k for k in volume.keys() if k != "name"), None)
                    if vol_type not in rules["allowed_types"]:
                        self.warnings.append(
                            {
                                "message": f"Volume '{name}' type '{vol_type}' not in allowed types",
                                "reason": f"Only volume types {rules['allowed_types']} are allowed for security and consistency.",
                                "fix": f"spec:\n  template:\n    spec:\n      volumes:\n      - name: {name}\n        {rules['allowed_types'][0]}:\n          name: <resource-name>  # Use an allowed volume type",
                            }
                        )

    def print_results(self):
        """Print validation results with enhanced UI"""
        if self.errors:
            console.print(
                Panel(
                    "Errors Found",
                    style="bold red",
                    border_style="red",
                    box=box.ROUNDED,
                )
            )
            for error in self.errors:
                table = Table(show_header=False, box=None)
                table.add_column("Field", style="bold red")
                table.add_column("Details")
                table.add_row("Message", error["message"])
                table.add_row("Reason", error["reason"])
                table.add_row("Fix", Text(error["fix"], style="green"))
                console.print(table)
                console.print()

        if self.warnings:
            console.print(
                Panel(
                    "Warnings",
                    style="bold yellow",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )
            for warning in self.warnings:
                table = Table(show_header=False, box=None)
                table.add_column("Field", style="bold yellow")
                table.add_column("Details")
                table.add_row("Message", warning["message"])
                table.add_row("Reason", warning["reason"])
                table.add_row("Fix", Text(warning["fix"], style="green"))
                console.print(table)
                console.print()

        if not self.errors and not self.warnings:
            console.print(
                Panel(
                    "✓ Manifest looks good!",
                    style="bold green",
                    border_style="green",
                    box=box.ROUNDED,
                )
            )


def main():
    if len(sys.argv) < 2:
        console.print(
            "[red]Usage: python k8s_validator.py <manifest_path> [<manifest_dir>][/red]"
        )
        sys.exit(1)

    manifest_path = sys.argv[1]
    manifest_dir = sys.argv[2] if len(sys.argv) > 2 else None
    validator = K8sValidator("validation_rules.yaml", manifest_dir)
    validator.validate_manifest(manifest_path)


if __name__ == "__main__":
    main()
