package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ValidationRule defines the structure of the validation rules in validation_rules.yaml
type ValidationRule struct {
    RequiredFields map[string][]string `yaml:"required_fields"`
    Namespace      struct {
        Required bool `yaml:"required"`
    } `yaml:"namespace"`
    Labels map[string]LabelRule `yaml:"labels"`
    Annotations map[string]AnnotationRule `yaml:"annotations"`
    Resources struct {
        Requests map[string]ResourceRule `yaml:"requests"`
        Limits   map[string]ResourceRule `yaml:"limits"`
    } `yaml:"resources"`
    Security struct {
        Pod      map[string]SecurityRule `yaml:"pod"`
        Container map[string]SecurityRule `yaml:"container"`
    } `yaml:"security"`
    RequireService bool `yaml:"require_service"`
    Images         struct {
        Registry string   `yaml:"registry"`
        NoLatest bool     `yaml:"no_latest"`
        Allowed  []string `yaml:"allowed"`
    } `yaml:"images"`
    Networking struct {
        PortsRequired bool   `yaml:"ports_required"`
        AllowedPorts  []int  `yaml:"allowed_ports"`
    } `yaml:"networking"`
    Probes struct {
        LivenessRequired  bool `yaml:"liveness_required"`
        ReadinessRequired bool `yaml:"readiness_required"`
    } `yaml:"probes"`
    Volumes struct {
        Required     bool     `yaml:"required"`
        AllowedTypes []string `yaml:"allowed_types"`
    } `yaml:"volumes"`
    ServiceMonitor struct {
        Required bool `yaml:"required"`
    } `yaml:"service_monitor"`
}

// LabelRule defines the structure for label rules
type LabelRule struct {
    Required      bool     `yaml:"required"`
    AllowedValues []string `yaml:"allowed_values"`
    Value         string   `yaml:"value"` // Keep for backward compatibility
}

// AnnotationRule defines the structure for annotation rules
type AnnotationRule struct {
    Required bool   `yaml:"required"`
    Value    string `yaml:"value"`
}

// ResourceRule defines the structure for resource rules
type ResourceRule struct {
    Required bool   `yaml:"required"`
    Min      string `yaml:"min,omitempty"`
    Max      string `yaml:"max,omitempty"`
}

// SecurityRule defines the structure for security rules
type SecurityRule struct {
    Required bool        `yaml:"required"`
    Value    interface{} `yaml:"value"`
}

// ValidationIssue represents an error or warning with a message, reason, and fix
type ValidationIssue struct {
    Type    string // "Error" or "Warning"
    Message string
    Reason  string
    Fix     string
}

// Validator holds the state of the validation process
type Validator struct {
    Rules    ValidationRule
    Errors   []ValidationIssue
    Warnings []ValidationIssue
    Manifest map[string]interface{}
    Kind     string
}

// ResourceValue helps compare resource values (e.g., "256Mi", "500m")
type ResourceValue struct {
    Value  float64
    Unit   string
    Raw    string
}

func parseResourceValue(value string) ResourceValue {
    if value == "" {
        return ResourceValue{Value: 0, Unit: "", Raw: "0"}
    }
    var num float64
    var unit string
    fmt.Sscanf(value, "%f%s", &num, &unit)
    return ResourceValue{Value: num, Unit: unit, Raw: value}
}

func (rv ResourceValue) LessThan(other ResourceValue) bool {
    if rv.Unit != other.Unit {
        return false // Can't compare different units
    }
    return rv.Value < other.Value
}

func (rv ResourceValue) GreaterThan(other ResourceValue) bool {
    if rv.Unit != other.Unit {
        return false
    }
    return rv.Value > other.Value
}

func (v *Validator) getNestedValue(obj map[string]interface{}, path string) interface{} {
    keys := strings.Split(path, ".")
    current := obj
    for _, key := range keys[:len(keys)-1] {
        if val, ok := current[key]; ok {
            if next, ok := val.(map[string]interface{}); ok {
                current = next
            } else {
                return nil
            }
        } else {
            return nil
        }
    }
    return current[keys[len(keys)-1]]
}

func (v *Validator) checkRequiredFields() {
    requiredFields := v.Rules.RequiredFields[v.Kind]
    for _, field := range requiredFields {
        if strings.Contains(field, ".") {
            if v.getNestedValue(v.Manifest, field) == nil {
                v.Errors = append(v.Errors, ValidationIssue{
                    Type:    "Error",
                    Message: fmt.Sprintf("Missing required field: %s", field),
                    Reason:  fmt.Sprintf("The field '%s' is required for %s resources to ensure proper configuration.", field, v.Kind),
                    Fix:     fmt.Sprintf("%s:\n  # Add the required field '%s'", field[:strings.LastIndex(field, ".")], field),
                })
            }
        } else if _, exists := v.Manifest[field]; !exists {
            v.Errors = append(v.Errors, ValidationIssue{
                Type:    "Error",
                Message: fmt.Sprintf("Missing required field: %s", field),
                Reason:  fmt.Sprintf("The field '%s' is required for %s resources to ensure proper configuration.", field, v.Kind),
                Fix:     fmt.Sprintf("%s: <value>\n  # Add the required field '%s'", field, field),
            })
        }
    }
}

func (v *Validator) checkNamespace() {
    metadata, ok := v.Manifest["metadata"].(map[string]interface{})
    if !ok {
        metadata = make(map[string]interface{})
    }
    actualNs, _ := metadata["namespace"].(string)
    if actualNs == "" {
        actualNs = "default"
    }

    if v.Rules.Namespace.Required && metadata["namespace"] == nil {
        v.Errors = append(v.Errors, ValidationIssue{
            Type:    "Error",
            Message: "Namespace is required but not specified",
            Reason:  "A namespace must be explicitly specified to ensure resources are deployed in the correct environment.",
            Fix:     "metadata:\n  namespace: <your-app-namespace>  # Specify your app's namespace",
        })
    }
    if actualNs == "default" {
        v.Errors = append(v.Errors, ValidationIssue{
            Type:    "Error",
            Message: "Namespace cannot be 'default'",
            Reason:  "Using the 'default' namespace is not allowed; specify a custom namespace for your app.",
            Fix:     "metadata:\n  namespace: <your-app-namespace>  # Replace 'default' with your app's namespace",
        })
    }
}

func (v *Validator) checkLabelsAnnotations() {
    metadata, ok := v.Manifest["metadata"].(map[string]interface{})
    if !ok {
        metadata = make(map[string]interface{})
    }
    labels, ok := metadata["labels"].(map[string]interface{})
    if !ok {
        labels = make(map[string]interface{})
    }
    annotations, ok := metadata["annotations"].(map[string]interface{})
    if !ok {
        annotations = make(map[string]interface{})
    }

    for key, rule := range v.Rules.Labels {
        actual, exists := labels[key]
        if rule.Required && !exists {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Required label '%s' missing", key),
                Reason:  fmt.Sprintf("The label '%s' is required for organizational consistency and resource identification.", key),
                Fix:     fmt.Sprintf("metadata:\n  labels:\n    %s: <value>  # Add the required label", key),
            })
        }
        // Check if the actual value is in the allowed values
        if len(rule.AllowedValues) > 0 {
            actualStr, ok := actual.(string)
            if !ok && exists {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Label '%s' must be a string, got '%v'", key, actual),
                    Reason:  fmt.Sprintf("The label '%s' must be a string value.", key),
                    Fix:     fmt.Sprintf("metadata:\n  labels:\n    %s: %s  # Set a valid string value", key, rule.AllowedValues[0]),
                })
                continue
            }
            if exists {
                found := false
                for _, allowed := range rule.AllowedValues {
                    if actualStr == allowed {
                        found = true
                        break
                    }
                }
                if !found {
                    v.Warnings = append(v.Warnings, ValidationIssue{
                        Type:    "Warning",
                        Message: fmt.Sprintf("Label '%s' must be one of %v, got '%s'", key, rule.AllowedValues, actualStr),
                        Reason:  fmt.Sprintf("The label '%s' must have one of the allowed values %v to meet organizational standards.", key, rule.AllowedValues),
                        Fix:     fmt.Sprintf("metadata:\n  labels:\n    %s: %s  # Set a valid value", key, rule.AllowedValues[0]),
                    })
                }
            }
        } else if rule.Value != "" && actual != rule.Value {
            // Fallback to single value check if allowed_values is not specified
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Label '%s' must be '%s', got '%v'", key, rule.Value, actual),
                Reason:  fmt.Sprintf("The label '%s' must have the value '%s' to meet organizational standards.", key, rule.Value),
                Fix:     fmt.Sprintf("metadata:\n  labels:\n    %s: %s  # Set the correct value", key, rule.Value),
            })
        }
    }

    for key, rule := range v.Rules.Annotations {
        actual, exists := annotations[key]
        if rule.Required && !exists {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Required annotation '%s' missing", key),
                Reason:  fmt.Sprintf("The annotation '%s' is required for metadata tracking and monitoring.", key),
                Fix:     fmt.Sprintf("metadata:\n  annotations:\n    %s: <value>  # Add the required annotation", key),
            })
        }
        if rule.Value != "" && actual != rule.Value {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Annotation '%s' must be '%s', got '%v'", key, rule.Value, actual),
                Reason:  fmt.Sprintf("The annotation '%s' must have the value '%s' to meet organizational standards.", key, rule.Value),
                Fix:     fmt.Sprintf("metadata:\n  annotations:\n    %s: %s  # Set the correct value", key, rule.Value),
            })
        }
    }
}

func (v *Validator) checkResourceLimits() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        resources, ok := cont["resources"].(map[string]interface{})
        if !ok {
            resources = make(map[string]interface{})
        }
        requests, ok := resources["requests"].(map[string]interface{})
        if !ok {
            requests = make(map[string]interface{})
        }
        limits, ok := resources["limits"].(map[string]interface{})
        if !ok {
            limits = make(map[string]interface{})
        }

        for res, rule := range v.Rules.Resources.Requests {
            actualVal, exists := requests[res]
            actual := parseResourceValue("")
            if exists {
                if strVal, ok := actualVal.(string); ok {
                    actual = parseResourceValue(strVal)
                }
            }
            if rule.Min != "" && actual.LessThan(parseResourceValue(rule.Min)) {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' %s request '%s' below min '%s'", name, res, actual.Raw, rule.Min),
                    Reason:  fmt.Sprintf("Resource requests for '%s' must be at least '%s' to ensure adequate resource allocation.", res, rule.Min),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        resources:\n          requests:\n            %s: %s  # Increase to at least the minimum", name, res, rule.Min),
                })
            }
            if rule.Required && !exists {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' missing %s request", name, res),
                    Reason:  fmt.Sprintf("A '%s' request is required to ensure the container has guaranteed resources.", res),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        resources:\n          requests:\n            %s: <value>  # Add the required request", name, res),
                })
            }
        }

        for res, rule := range v.Rules.Resources.Limits {
            actualVal, exists := limits[res]
            actual := parseResourceValue("")
            if exists {
                if strVal, ok := actualVal.(string); ok {
                    actual = parseResourceValue(strVal)
                }
            }
            if rule.Max != "" && actual.GreaterThan(parseResourceValue(rule.Max)) {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' %s limit '%s' above max '%s'", name, res, actual.Raw, rule.Max),
                    Reason:  fmt.Sprintf("Resource limits for '%s' must not exceed '%s' to prevent over-allocation.", res, rule.Max),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        resources:\n          limits:\n            %s: %s  # Decrease to at most the maximum", name, res, rule.Max),
                })
            }
            if rule.Required && !exists {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' missing %s limit", name, res),
                    Reason:  fmt.Sprintf("A '%s' limit is required to prevent resource over-usage.", res),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        resources:\n          limits:\n            %s: <value>  # Add the required limit", name, res),
                })
            }
        }
    }
}

func (v *Validator) checkSecurityContext() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }
    podSC, ok := podSpec["securityContext"].(map[string]interface{})
    if !ok {
        podSC = make(map[string]interface{})
    }

    for key, rule := range v.Rules.Security.Pod {
        actual := podSC[key]
        if rule.Required && actual == nil {
            v.Errors = append(v.Errors, ValidationIssue{
                Type:    "Error",
                Message: fmt.Sprintf("Pod securityContext.%s is required", key),
                Reason:  fmt.Sprintf("The pod-level security context setting '%s' is required for security compliance.", key),
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      securityContext:\n        %s: <value>  # Add the required setting", key),
            })
        }
        if rule.Value != nil && actual != rule.Value {
            v.Errors = append(v.Errors, ValidationIssue{
                Type:    "Error",
                Message: fmt.Sprintf("Pod securityContext.%s must be %v, got %v", key, rule.Value, actual),
                Reason:  fmt.Sprintf("The pod-level security context setting '%s' must be %v for security compliance.", key, rule.Value),
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      securityContext:\n        %s: %v  # Set the correct value", key, rule.Value),
            })
        }
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        contSC, ok := cont["securityContext"].(map[string]interface{})
        if !ok {
            contSC = make(map[string]interface{})
        }

        for key, rule := range v.Rules.Security.Container {
            actual := contSC[key]
            if rule.Required && actual == nil {
                v.Errors = append(v.Errors, ValidationIssue{
                    Type:    "Error",
                    Message: fmt.Sprintf("Container '%s' securityContext.%s is required", name, key),
                    Reason:  fmt.Sprintf("The container-level security context setting '%s' is required for security compliance.", key),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        securityContext:\n          %s: <value>  # Add the required setting", name, key),
                })
            }
            if rule.Value != nil && actual != rule.Value {
                v.Errors = append(v.Errors, ValidationIssue{
                    Type:    "Error",
                    Message: fmt.Sprintf("Container '%s' securityContext.%s must be %v, got %v", name, key, rule.Value, actual),
                    Reason:  fmt.Sprintf("The container-level security context setting '%s' must be %v for security compliance.", key, rule.Value),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        securityContext:\n          %s: %v  # Set the correct value", name, key, rule.Value),
                })
            }
        }
    }
}

func (v *Validator) checkServiceRelationship(allManifests []map[string]interface{}) {
    if v.Kind != "deployment" || !v.Rules.RequireService {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    selector, ok := spec["selector"].(map[string]interface{})
    if !ok {
        return
    }
    matchLabels, ok := selector["matchLabels"].(map[string]interface{})
    if !ok {
        return
    }

    serviceFound := false
    for _, other := range allManifests {
        if otherKind, ok := other["kind"].(string); ok && strings.ToLower(otherKind) == "service" {
            otherSpec, ok := other["spec"].(map[string]interface{})
            if !ok {
                continue
            }
            svcSelector, ok := otherSpec["selector"].(map[string]interface{})
            if !ok {
                continue
            }
            if fmt.Sprintf("%v", svcSelector) == fmt.Sprintf("%v", matchLabels) {
                serviceFound = true
                break
            }
        }
    }

    if !serviceFound {
        // Marshal matchLabels to YAML
        labelsYAML, err := yaml.Marshal(matchLabels)
        if err != nil {
            // If marshaling fails, provide a fallback message
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: "Deployment missing corresponding Service with matching selector",
                Reason:  "A Service is required to expose the Deployment's pods to the network.",
                Fix:     "apiVersion: v1\nkind: Service\nmetadata:\n  name: <service-name>\nspec:\n  selector:\n    # Unable to marshal selector labels due to error\n  ports:\n  - protocol: TCP\n    port: 80\n    targetPort: 80  # Create a Service with matching selector",
            })
            return
        }

        // Convert the marshaled YAML (which is []byte) to a string
        labelsYAMLStr := string(labelsYAML)

        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: "Deployment missing corresponding Service with matching selector",
            Reason:  "A Service is required to expose the Deployment's pods to the network.",
            Fix:     fmt.Sprintf("apiVersion: v1\nkind: Service\nmetadata:\n  name: <service-name>\nspec:\n  selector:\n    %s  ports:\n  - protocol: TCP\n    port: 80\n    targetPort: 80  # Create a Service with matching selector", labelsYAMLStr),
        })
    }
}

func (v *Validator) checkImagePolicies() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        image, ok := cont["image"].(string)
        if !ok {
            image = ""
        }

        if v.Rules.Images.Registry != "" && !strings.HasPrefix(image, v.Rules.Images.Registry) {
            v.Errors = append(v.Errors, ValidationIssue{
                Type:    "Error",
                Message: fmt.Sprintf("Container '%s' image '%s' must use registry '%s'", name, image, v.Rules.Images.Registry),
                Reason:  fmt.Sprintf("All images must come from the approved registry '%s' for security and compliance.", v.Rules.Images.Registry),
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        image: %s<image-name>:<tag>  # Use the approved registry", name, v.Rules.Images.Registry),
            })
        }
        if v.Rules.Images.NoLatest && strings.Contains(image, ":latest") {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Container '%s' image '%s' uses 'latest' tag", name, image),
                Reason:  "Using the 'latest' tag can lead to unpredictable deployments; specify a specific version.",
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        image: %s  # Replace 'latest' with a specific version", name, strings.Replace(image, ":latest", ":<specific-version>", 1)),
            })
        }
        if len(v.Rules.Images.Allowed) > 0 {
            allowed := false
            for _, allowedImage := range v.Rules.Images.Allowed {
                if image == allowedImage {
                    allowed = true
                    break
                }
            }
            if !allowed {
                v.Errors = append(v.Errors, ValidationIssue{
                    Type:    "Error",
                    Message: fmt.Sprintf("Container '%s' image '%s' not in allowed list", name, image),
                    Reason:  fmt.Sprintf("Only approved images are allowed: %v.", v.Rules.Images.Allowed),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        image: %s  # Use an approved image", name, v.Rules.Images.Allowed[0]),
                })
            }
        }
    }
}

func (v *Validator) checkNetworking() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        ports, ok := cont["ports"].([]interface{})
        if !ok {
            ports = []interface{}{}
        }

        if v.Rules.Networking.PortsRequired && len(ports) == 0 {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Container '%s' missing port definitions", name),
                Reason:  "Port definitions are required to expose the container to the network.",
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        ports:\n        - containerPort: 80  # Add port definitions", name),
            })
        }
        for _, port := range ports {
            p, ok := port.(map[string]interface{})
            if !ok {
                continue
            }
            containerPort, ok := p["containerPort"].(int)
            if !ok {
                continue
            }
            if len(v.Rules.Networking.AllowedPorts) > 0 {
                allowed := false
                for _, allowedPort := range v.Rules.Networking.AllowedPorts {
                    if containerPort == allowedPort {
                        allowed = true
                        break
                    }
                }
                if !allowed {
                    v.Warnings = append(v.Warnings, ValidationIssue{
                        Type:    "Warning",
                        Message: fmt.Sprintf("Container '%s' port %d not in allowed list", name, containerPort),
                        Reason:  fmt.Sprintf("Only ports %v are allowed for security and consistency.", v.Rules.Networking.AllowedPorts),
                        Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        ports:\n        - containerPort: %d  # Use an allowed port", name, v.Rules.Networking.AllowedPorts[0]),
                    })
                }
            }
        }
    }
}

func (v *Validator) checkProbes() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        liveness := cont["livenessProbe"]
        readiness := cont["readinessProbe"]

        if v.Rules.Probes.LivenessRequired && liveness == nil {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Container '%s' missing liveness probe", name),
                Reason:  "A liveness probe is required to ensure the container is running correctly.",
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        livenessProbe:\n          httpGet:\n            path: /health\n            port: 80\n          initialDelaySeconds: 15\n          periodSeconds: 10  # Add a liveness probe", name),
            })
        }
        if v.Rules.Probes.ReadinessRequired && readiness == nil {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Container '%s' missing readiness probe", name),
                Reason:  "A readiness probe is required to ensure the container is ready to serve traffic.",
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        readinessProbe:\n          httpGet:\n            path: /ready\n            port: 80\n          initialDelaySeconds: 5\n          periodSeconds: 10  # Add a readiness probe", name),
            })
        }
    }
}

func (v *Validator) checkVolumes() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    volumes, ok := podSpec["volumes"].([]interface{})
    if !ok {
        volumes = []interface{}{}
    }

    if v.Rules.Volumes.Required && len(volumes) == 0 {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: "Volumes are required but none defined",
            Reason:  "Volumes are required for persistent storage or configuration.",
            Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      volumes:\n      - name: <volume-name>\n        configMap:\n          name: <configmap-name>  # Add a volume"),
        })
    }

    for _, volume := range volumes {
        vol, ok := volume.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := vol["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        if len(v.Rules.Volumes.AllowedTypes) > 0 {
            volType := ""
            for key := range vol {
                if key != "name" {
                    volType = key
                    break
                }
            }
            allowed := false
            for _, allowedType := range v.Rules.Volumes.AllowedTypes {
                if volType == allowedType {
                    allowed = true
                    break
                }
            }
            if !allowed {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Volume '%s' type '%s' not in allowed types", name, volType),
                    Reason:  fmt.Sprintf("Only volume types %v are allowed for security and consistency.", v.Rules.Volumes.AllowedTypes),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      volumes:\n      - name: %s\n        %s:\n          name: <resource-name>  # Use an allowed volume type", name, v.Rules.Volumes.AllowedTypes[0]),
                })
            }
        }
    }
}

func (v *Validator) checkServiceMonitor(allManifests []map[string]interface{}) {
    if !v.Rules.ServiceMonitor.Required {
        return
    }

    serviceMonitorFound := false
    for _, manifest := range allManifests {
        if kind, ok := manifest["kind"].(string); ok && kind == "ServiceMonitor" {
            apiVersion, ok := manifest["apiVersion"].(string)
            if ok && apiVersion == "monitoring.coreos.com/v1" {
                serviceMonitorFound = true
                break
            }
        }
    }

    if !serviceMonitorFound {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: "Missing required ServiceMonitor resource",
            Reason:  "A ServiceMonitor is required to enable Prometheus monitoring for the application.",
            Fix:     "apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nmetadata:\n  labels:\n    app: <app-name>\n    owner: <owner-name>\n    prometheus-enabled: \"true\"\n    release: prometheus-operator\n  name: servicemonitor\n  namespace: <namespace>\nspec:\n  endpoints:\n  - interval: 30s\n    path: /prometheus\n    port: app-port\n    scheme: http\n  namespaceSelector:\n    matchNames:\n    - default\n  selector:\n    matchLabels:\n      app: <app-name>\n      owner: <owner-name>",
        })
        return
    }
}

func (v *Validator) checkDeploymentReplicas() {
    if v.Kind != "deployment" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }

    replicas, ok := spec["replicas"].(int)
    if !ok {
        // If replicas is not an int, it might be a float64 due to YAML unmarshaling
        if replicasFloat, ok := spec["replicas"].(float64); ok {
            replicas = int(replicasFloat)
        } else {
            return
        }
    }

    if replicas < 3 {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: fmt.Sprintf("Deployment replicas should be at least 3, got %d", replicas),
            Reason:  "Deployments should typically use 3 replicas to ensure high availability and facilitate scaling.",
            Fix:     "spec:\n  replicas: 3  # Set replicas to at least 3",
        })
    }
}

func (v *Validator) checkPodDisruptionBudget(allManifests []map[string]interface{}) {
    if v.Kind != "poddisruptionbudget" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }

    // Check minAvailable or maxUnavailable
    minAvailable, minOk := spec["minAvailable"].(int)
    maxUnavailable, maxOk := spec["maxUnavailable"].(int)

    if !minOk && !maxOk {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: "PodDisruptionBudget must specify either minAvailable or maxUnavailable",
            Reason:  "A PDB must define disruption limits to allow node rolls and maintenance.",
            Fix:     "spec:\n  minAvailable: 1  # Set minAvailable or maxUnavailable",
        })
        return
    }

    // Ensure the PDB allows at least one disruption
    if minOk && minAvailable >= 3 {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: fmt.Sprintf("PodDisruptionBudget minAvailable %d may prevent node rolls", minAvailable),
            Reason:  "A PDB with a high minAvailable may prevent node rolls; consider using maxUnavailable instead.",
            Fix:     "spec:\n  maxUnavailable: 1  # Allow at least one disruption",
        })
    }

    // Check maxUnavailable to ensure it allows at least one disruption
    if maxOk && maxUnavailable == 0 {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: fmt.Sprintf("PodDisruptionBudget maxUnavailable %d prevents node rolls", maxUnavailable),
            Reason:  "A PDB with maxUnavailable set to 0 prevents node rolls; it should allow at least one disruption.",
            Fix:     "spec:\n  maxUnavailable: 1  # Allow at least one disruption",
        })
    }

    // Check for crash loop backoff (simulated via annotation for now)
    for _, manifest := range allManifests {
        if kind, ok := manifest["kind"].(string); ok && strings.ToLower(kind) == "pod" {
            metadata, ok := manifest["metadata"].(map[string]interface{})
            if !ok {
                continue
            }
            annotations, ok := metadata["annotations"].(map[string]interface{})
            if !ok {
                continue
            }
            if status, ok := annotations["crash-loop-backoff"].(string); ok && status == "true" {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: "PodDisruptionBudget should be removed for pods in crash loop backoff",
                    Reason:  "Pods in crash loop backoff should not have a PDB to allow rescheduling.",
                    Fix:     "# Remove the PodDisruptionBudget for this application",
                })
                break
            }
        }
    }
}

func (v *Validator) checkDeploymentPDB(allManifests []map[string]interface{}) {
    if v.Kind != "deployment" {
        return
    }

    // Check if the Deployment is in crash loop backoff (simulated via annotation)
    metadata, ok := v.Manifest["metadata"].(map[string]interface{})
    if !ok {
        return
    }
    annotations, ok := metadata["annotations"].(map[string]interface{})
    if !ok {
        annotations = make(map[string]interface{})
    }
    if status, ok := annotations["crash-loop-backoff"].(string); ok && status == "true" {
        // Check if a PDB exists; if so, warn to remove it
        deploymentName, _ := metadata["name"].(string)
        for _, manifest := range allManifests {
            if kind, ok := manifest["kind"].(string); ok && strings.ToLower(kind) == "poddisruptionbudget" {
                pdbMetadata, ok := manifest["metadata"].(map[string]interface{})
                if !ok {
                    continue
                }
                pdbName, _ := pdbMetadata["name"].(string)
                if strings.Contains(pdbName, deploymentName) { // Simple name matching for now
                    v.Warnings = append(v.Warnings, ValidationIssue{
                        Type:    "Warning",
                        Message: fmt.Sprintf("Deployment '%s' in crash loop backoff should not have a PodDisruptionBudget", deploymentName),
                        Reason:  "Pods in crash loop backoff should not have a PDB to allow rescheduling.",
                        Fix:     fmt.Sprintf("# Remove the PodDisruptionBudget for Deployment '%s'", deploymentName),
                    })
                    return
                }
            }
        }
        return // No PDB, which is correct for crash loop backoff
    }

    // If not in crash loop backoff, ensure a PDB exists
    deploymentName, _ := metadata["name"].(string)
    pdbFound := false
    for _, manifest := range allManifests {
        if kind, ok := manifest["kind"].(string); ok && strings.ToLower(kind) == "poddisruptionbudget" {
            pdbMetadata, ok := manifest["metadata"].(map[string]interface{})
            if !ok {
                continue
            }
            pdbName, _ := pdbMetadata["name"].(string)
            if strings.Contains(pdbName, deploymentName) { // Simple name matching for now
                pdbFound = true
                break
            }
        }
    }

    if !pdbFound {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: fmt.Sprintf("Deployment '%s' missing a PodDisruptionBudget", deploymentName),
            Reason:  "A PodDisruptionBudget is required to allow appropriate disruptions (e.g., node rolls) for the Deployment.",
            Fix:     fmt.Sprintf("apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: %s-pdb\nspec:\n  minAvailable: 1\n  selector:\n    matchLabels:\n      app: %s  # Adjust selector to match Deployment labels", deploymentName, deploymentName),
        })
    }
}

func (v *Validator) checkHPAReplicas(allManifests []map[string]interface{}) {
    if v.Kind != "deployment" {
        return
    }

    // Check if an HPA exists for this Deployment
    deploymentName, _ := v.Manifest["metadata"].(map[string]interface{})["name"].(string)
    hpaFound := false
    for _, manifest := range allManifests {
        if kind, ok := manifest["kind"].(string); ok && strings.ToLower(kind) == "horizontalpodautoscaler" {
            spec, ok := manifest["spec"].(map[string]interface{})
            if !ok {
                continue
            }
            targetRef, ok := spec["scaleTargetRef"].(map[string]interface{})
            if !ok {
                continue
            }
            if targetKind, ok := targetRef["kind"].(string); ok && strings.ToLower(targetKind) == "deployment" {
                if targetName, ok := targetRef["name"].(string); ok && targetName == deploymentName {
                    hpaFound = true
                    break
                }
            }
        }
    }

    if !hpaFound {
        return
    }

    // Check if replicas is specified
    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    if _, exists := spec["replicas"]; exists {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: "Deployment should not specify replicas when using an HPA",
            Reason:  "When using an HorizontalPodAutoscaler, replicas should be managed by the HPA, not specified in the Deployment.",
            Fix:     "spec:\n  # Remove the replicas field to allow HPA to manage scaling",
        })
    }
}

func (v *Validator) checkStartupProbe() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        if _, exists := cont["startupProbe"]; !exists {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Container '%s' missing startup probe", name),
                Reason:  "A startup probe is recommended to ensure fast application startup, facilitating scaling, self-healing, and maintenance.",
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        startupProbe:\n          httpGet:\n            path: /health\n            port: 80\n          initialDelaySeconds: 5\n          periodSeconds: 5  # Add a startup probe", name),
            })
        }
    }
}

func (v *Validator) checkLivenessProbeDependencies() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        livenessProbe, ok := cont["livenessProbe"].(map[string]interface{})
        if !ok {
            continue
        }
        exec, ok := livenessProbe["exec"].(map[string]interface{})
        if !ok {
            continue
        }
        command, ok := exec["command"].([]interface{})
        if !ok {
            continue
        }
        for _, cmd := range command {
            cmdStr, ok := cmd.(string)
            if !ok {
                continue
            }
            if strings.Contains(cmdStr, "curl") || strings.Contains(cmdStr, "wget") || strings.Contains(cmdStr, "http") {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' liveness probe may check external dependencies", name),
                    Reason:  "Liveness probes should not check external dependencies to prevent the stampeding herd problem and reduce stress on the control plane.",
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        livenessProbe:\n          httpGet:\n            path: /health\n            port: 80\n          initialDelaySeconds: 15\n          periodSeconds: 10  # Use a local health check", name),
                })
                break
            }
        }
    }
}

func (v *Validator) checkProbeRetryRandomness() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        for _, probeType := range []string{"livenessProbe", "readinessProbe"} {
            probe, ok := cont[probeType].(map[string]interface{})
            if !ok {
                continue
            }
            periodSeconds, ok := probe["periodSeconds"].(int)
            if !ok {
                continue
            }
            if periodSeconds > 0 && periodSeconds <= 10 {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' %s may have fixed retry intervals", name, probeType),
                    Reason:  "Retries in a cloud-native system should have a degree of randomness to prevent a flood of requests; consider using a random interval.",
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        %s:\n          periodSeconds: 15  # Use a longer interval with randomness in application logic", name, probeType),
                })
            }
        }
    }
}

func (v *Validator) checkLongLivedConnections() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, ok := v.Manifest["spec"].(map[string]interface{})
    if !ok {
        return
    }
    template, ok := spec["template"].(map[string]interface{})
    if !ok {
        return
    }
    podSpec, ok := template["spec"].(map[string]interface{})
    if !ok {
        return
    }
    containers, ok := podSpec["containers"].([]interface{})
    if !ok {
        return
    }

    for _, container := range containers {
        cont, ok := container.(map[string]interface{})
        if !ok {
            continue
        }
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        for _, probeType := range []string{"livenessProbe", "readinessProbe"} {
            probe, ok := cont[probeType].(map[string]interface{})
            if !ok {
                continue
            }
            httpGet, ok := probe["httpGet"].(map[string]interface{})
            if !ok {
                continue
            }
            headers, ok := httpGet["httpHeaders"].([]interface{})
            if !ok {
                continue
            }
            for _, header := range headers {
                h, ok := header.(map[string]interface{})
                if !ok {
                    continue
                }
                name, _ := h["name"].(string)
                value, _ := h["value"].(string)
                if strings.ToLower(name) == "connection" && strings.ToLower(value) == "keep-alive" {
                    v.Warnings = append(v.Warnings, ValidationIssue{
                        Type:    "Warning",
                        Message: fmt.Sprintf("Container '%s' %s uses keep-alive, indicating potential long-lived connections", name, probeType),
                        Reason:  "Long-lived connections between services in Kubernetes can create hotspots; consider using short-lived connections.",
                        Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        %s:\n          httpGet:\n            httpHeaders:\n            - name: Connection\n              value: close  # Use short-lived connections", name, probeType),
                    })
                    break
                }
            }
        }
    }
}

// Bubble Tea Model for Interactive UI
type model struct {
    validator    *Validator
    issues       []ValidationIssue
    currentIndex int
    quit         bool
}

// Styles for the UI
var (
    headerStyle = lipgloss.NewStyle().
        Bold(true).
        Foreground(lipgloss.Color("205")). // Purple
        Padding(0, 1)

    errorTypeStyle = lipgloss.NewStyle().
        Background(lipgloss.Color("9")). // Red
        Foreground(lipgloss.Color("0")). // Black
        Padding(0, 1)

    warningTypeStyle = lipgloss.NewStyle().
        Background(lipgloss.Color("11")). // Yellow
        Foreground(lipgloss.Color("0")).  // Black
        Padding(0, 1)

    messageStyle = lipgloss.NewStyle().
        Bold(true).
        Foreground(lipgloss.Color("15")) // White

    reasonStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("245")). // Light gray
        Width(110).                       // Increased width
        Align(lipgloss.Left)

    fixStyle = lipgloss.NewStyle().
        Background(lipgloss.Color("236")). // Dark gray
        Foreground(lipgloss.Color("10")).  // Green
        Padding(1).
        MarginTop(1).
        Width(110) // Increased width

    progressStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("205")). // Purple
        Width(110)                        // Increased width

    navStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("240")). // Gray
        Italic(true).
        MarginTop(1)

    containerStyle = lipgloss.NewStyle().
        Border(lipgloss.RoundedBorder()).
        BorderForeground(lipgloss.Color("205")). // Purple
        Padding(1).
        Margin(1).
        Width(120) // Increased container width
)

func (m model) Init() tea.Cmd {
    return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "q", "ctrl+c":
            // Only quit if the user has seen at least one issue or there are no issues
            if len(m.issues) == 0 || m.currentIndex > 0 {
                m.quit = true
                return m, tea.Quit
            }
        case "up", "k":
            if m.currentIndex > 0 {
                m.currentIndex--
            }
        case "down", "j":
            if m.currentIndex < len(m.issues)-1 {
                m.currentIndex++
            }
        }
    }
    return m, nil
}

func (m model) View() string {
    if m.quit {
        return lipgloss.NewStyle().
            Foreground(lipgloss.Color("42")).
            Render("Validation complete. Goodbye!\n")
    }

    if len(m.issues) == 0 {
        return lipgloss.NewStyle().
            Foreground(lipgloss.Color("42")).
            Render("✓ Manifest looks good!\n")
    }

    issue := m.issues[m.currentIndex]

    // Header
    header := headerStyle.Render(fmt.Sprintf("Validation Issues (%d/%d)", m.currentIndex+1, len(m.issues)))

    // Type and Message
    typeStyle := errorTypeStyle
    if issue.Type == "Warning" {
        typeStyle = warningTypeStyle
    }
    typeLabel := typeStyle.Render(issue.Type)
    message := messageStyle.Render(issue.Message)
    typeMessage := lipgloss.JoinHorizontal(lipgloss.Left, typeLabel, " ", message)

    // Reason
    reason := reasonStyle.Render("Reason: " + issue.Reason)

    // Fix (with proper indentation)
    fixLines := strings.Split(issue.Fix, "\n")
    indentedFix := strings.Join(fixLines, "\n")
    fix := fixStyle.Render(indentedFix)

    // Progress Bar
    total := len(m.issues)
    current := m.currentIndex + 1
    progress := progressStyle.Render(progressBar(110, current, total)) // Match the width

    // Navigation Instructions
    nav := navStyle.Render("Use ↑/↓ or k/j to navigate, q to quit.")

    // Combine all parts into a container with proper spacing
    content := lipgloss.JoinVertical(
        lipgloss.Left,
        header,
        "", // Add a blank line for spacing
        typeMessage,
        reason,
        "", // Add a blank line for spacing
        fix,
        "", // Add a blank line for spacing
        progress,
        "", // Add a blank line for spacing
        nav,
    )

    return containerStyle.Render(content) + "\n"
}

// progressBar generates a simple progress bar
func progressBar(width, current, total int) string {
    if total == 0 {
        return ""
    }
    filled := int(float64(width) * float64(current) / float64(total))
    empty := width - filled
    return "[" + strings.Repeat("█", filled) + strings.Repeat(" ", empty) + "]"
}

func validateManifest(manifestPath, manifestDir string) error {
    // Load validation rules from the parent directory
    rulesFile, err := os.ReadFile("../validation_rules.yaml")
    if err != nil {
        return fmt.Errorf("error loading validation rules: %v", err)
    }

    var rules ValidationRule
    if err := yaml.Unmarshal(rulesFile, &rules); err != nil {
        return fmt.Errorf("error parsing validation rules: %v", err)
    }

    // Load all manifests from directory for cross-referencing
    var allManifests []map[string]interface{}
    if manifestDir != "" {
        err = filepath.Walk(manifestDir, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
                data, err := os.ReadFile(path)
                if err != nil {
                    return err
                }
                var manifest map[string]interface{}
                if err := yaml.Unmarshal(data, &manifest); err != nil {
                    return err
                }
                if manifest != nil {
                    allManifests = append(allManifests, manifest)
                }
            }
            return nil
        })
        if err != nil {
            return fmt.Errorf("error loading manifests from directory: %v", err)
        }
    }

    // Load the target manifest
    data, err := os.ReadFile(manifestPath)
    if err != nil {
        return fmt.Errorf("error reading manifest: %v", err)
    }

    // Decode multiple YAML documents
    var manifests []map[string]interface{}
    decoder := yaml.NewDecoder(bytes.NewReader(data))
    for {
        var manifest map[string]interface{}
        err := decoder.Decode(&manifest)
        if err != nil {
            if err == io.EOF {
                break
            }
            return fmt.Errorf("error parsing manifest document: %v", err)
        }
        if manifest != nil {
            manifests = append(manifests, manifest)
        }
    }

    // Add the manifests from test.yaml to allManifests
    allManifests = append(allManifests, manifests...)

    // Process each manifest individually
    var allIssues []ValidationIssue
    for _, manifest := range manifests {
        if manifest == nil {
            continue
        }

        kind, ok := manifest["kind"].(string)
        if !ok {
            continue
        }

        validator := &Validator{
            Rules:    rules,
            Manifest: manifest,
            Kind:     strings.ToLower(kind),
        }

        // Run validation checks that apply to individual manifests
        validator.checkRequiredFields()
        validator.checkNamespace()
        validator.checkLabelsAnnotations()
        validator.checkResourceLimits()
        validator.checkSecurityContext()
        validator.checkServiceRelationship(allManifests)
        validator.checkImagePolicies()
        validator.checkNetworking()
        validator.checkProbes()
        validator.checkVolumes()
        validator.checkDeploymentReplicas()
        validator.checkPodDisruptionBudget(allManifests)
        validator.checkHPAReplicas(allManifests)
        validator.checkStartupProbe()
        validator.checkLivenessProbeDependencies()
        validator.checkProbeRetryRandomness()
        validator.checkLongLivedConnections()
        validator.checkDeploymentPDB(allManifests)

        // Collect issues from this manifest
        allIssues = append(allIssues, validator.Errors...)
        allIssues = append(allIssues, validator.Warnings...)
    }

    // Run cross-manifest validations (like ServiceMonitor) once after processing all manifests
    validator := &Validator{
        Rules: rules,
    }
    validator.checkServiceMonitor(allManifests)
    allIssues = append(allIssues, validator.Errors...)
    allIssues = append(allIssues, validator.Warnings...)

    // If no issues, add a "looks good" message
    if len(allIssues) == 0 {
        allIssues = []ValidationIssue{
            {
                Type:    "Info",
                Message: "✓ Manifest looks good!",
                Reason:  "No validation issues were found.",
                Fix:     "",
            },
        }
    }

    // Start the Bubble Tea UI with all collected issues
    p := tea.NewProgram(model{validator: validator, issues: allIssues, currentIndex: 0, quit: false})
    if _, err := p.Run(); err != nil {
        return fmt.Errorf("error running UI: %v", err)
    }

    return nil
}

var rootCmd = &cobra.Command{
    Use:   "k8s-validator <manifest_path> [manifest_dir]",
    Short: "Validate Kubernetes manifests against organizational rules",
    Args:  cobra.MinimumNArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        manifestPath := args[0]
        manifestDir := ""
        if len(args) > 1 {
            manifestDir = args[1]
        }
        return validateManifest(manifestPath, manifestDir)
    },
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}