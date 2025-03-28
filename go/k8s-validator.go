package main

import (
    "fmt"
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
    RequiredFields map[string][]string            `yaml:"required_fields"`
    Namespace      struct{ Required bool }        `yaml:"namespace"`
    Labels         map[string]struct {            `yaml:"labels"`
        Required bool   `yaml:"required"`
        Value    string `yaml:"value"`
    }
    Annotations map[string]struct {            `yaml:"annotations"`
        Required bool   `yaml:"required"`
        Value    string `yaml:"value"`
    }
    Resources struct { `yaml:"resources"`
        Requests map[string]struct { `yaml:"requests"`
            Required bool   `yaml:"required"`
            Min      string `yaml:"min"`
        }
        Limits map[string]struct { `yaml:"limits"`
            Required bool   `yaml:"required"`
            Max      string `yaml:"max"`
        }
    }
    Security struct { `yaml:"security"`
        Pod      map[string]struct { `yaml:"pod"`
            Required bool        `yaml:"required"`
            Value    interface{} `yaml:"value"`
        }
        Container map[string]struct { `yaml:"container"`
            Required bool        `yaml:"required"`
            Value    interface{} `yaml:"value"`
        }
    }
    RequireService bool `yaml:"require_service"`
    Images         struct { `yaml:"images"`
        Registry string   `yaml:"registry"`
        NoLatest bool     `yaml:"no_latest"`
        Allowed  []string `yaml:"allowed"`
    }
    Networking struct { `yaml:"networking"`
        PortsRequired bool     `yaml:"ports_required"`
        AllowedPorts  []int    `yaml:"allowed_ports"`
    }
    Probes struct { `yaml:"probes"`
        LivenessRequired  bool `yaml:"liveness_required"`
        ReadinessRequired bool `yaml:"readiness_required"`
    }
    Volumes struct { `yaml:"volumes"`
        Required     bool     `yaml:"required"`
        AllowedTypes []string `yaml:"allowed_types"`
    }
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
    metadata, _ := v.Manifest["metadata"].(map[string]interface{})
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
    metadata, _ := v.Manifest["metadata"].(map[string]interface{})
    labels, _ := metadata["labels"].(map[string]interface{})
    annotations, _ := metadata["annotations"].(map[string]interface{})

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
        if rule.Value != "" && actual != rule.Value {
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

    spec, _ := v.Manifest["spec"].(map[string]interface{})
    template, _ := spec["template"].(map[string]interface{})
    podSpec, _ := template["spec"].(map[string]interface{})
    containers, _ := podSpec["containers"].([]interface{})

    for _, container := range containers {
        cont, _ := container.(map[string]interface{})
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        resources, _ := cont["resources"].(map[string]interface{})
        requests, _ := resources["requests"].(map[string]interface{})
        limits, _ := resources["limits"].(map[string]interface{})

        for res, rule := range v.Rules.Resources.Requests {
            actual := parseResourceValue(requests[res].(string))
            if rule.Min != "" && actual.LessThan(parseResourceValue(rule.Min)) {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' %s request '%s' below min '%s'", name, res, actual.Raw, rule.Min),
                    Reason:  fmt.Sprintf("Resource requests for '%s' must be at least '%s' to ensure adequate resource allocation.", res, rule.Min),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        resources:\n          requests:\n            %s: %s  # Increase to at least the minimum", name, res, rule.Min),
                })
            }
            if rule.Required && requests[res] == nil {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' missing %s request", name, res),
                    Reason:  fmt.Sprintf("A '%s' request is required to ensure the container has guaranteed resources.", res),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        resources:\n          requests:\n            %s: <value>  # Add the required request", name, res),
                })
            }
        }

        for res, rule := range v.Rules.Resources.Limits {
            actual := parseResourceValue(limits[res].(string))
            if rule.Max != "" && actual.GreaterThan(parseResourceValue(rule.Max)) {
                v.Warnings = append(v.Warnings, ValidationIssue{
                    Type:    "Warning",
                    Message: fmt.Sprintf("Container '%s' %s limit '%s' above max '%s'", name, res, actual.Raw, rule.Max),
                    Reason:  fmt.Sprintf("Resource limits for '%s' must not exceed '%s' to prevent over-allocation.", res, rule.Max),
                    Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        resources:\n          limits:\n            %s: %s  # Decrease to at most the maximum", name, res, rule.Max),
                })
            }
            if rule.Required && limits[res] == nil {
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

    spec, _ := v.Manifest["spec"].(map[string]interface{})
    template, _ := spec["template"].(map[string]interface{})
    podSpec, _ := template["spec"].(map[string]interface{})
    containers, _ := podSpec["containers"].([]interface{})
    podSC, _ := podSpec["securityContext"].(map[string]interface{})

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
        cont, _ := container.(map[string]interface{})
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        contSC, _ := cont["securityContext"].(map[string]interface{})

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

    spec, _ := v.Manifest["spec"].(map[string]interface{})
    selector, _ := spec["selector"].(map[string]interface{})
    matchLabels, _ := selector["matchLabels"].(map[string]interface{})

    serviceFound := false
    for _, other := range allManifests {
        if otherKind, _ := other["kind"].(string); strings.ToLower(otherKind) == "service" {
            otherSpec, _ := other["spec"].(map[string]interface{})
            svcSelector, _ := otherSpec["selector"].(map[string]interface{})
            if fmt.Sprintf("%v", svcSelector) == fmt.Sprintf("%v", matchLabels) {
                serviceFound = true
                break
            }
        }
    }

    if !serviceFound {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: "Deployment missing corresponding Service with matching selector",
            Reason:  "A Service is required to expose the Deployment's pods to the network.",
            Fix:     fmt.Sprintf("apiVersion: v1\nkind: Service\nmetadata:\n  name: <service-name>\nspec:\n  selector:\n    %s\n  ports:\n  - protocol: TCP\n    port: 80\n    targetPort: 80  # Create a Service with matching selector", yaml.Marshal(matchLabels)),
        })
    }
}

func (v *Validator) checkImagePolicies() {
    if v.Kind != "deployment" && v.Kind != "pod" {
        return
    }

    spec, _ := v.Manifest["spec"].(map[string]interface{})
    template, _ := spec["template"].(map[string]interface{})
    podSpec, _ := template["spec"].(map[string]interface{})
    containers, _ := podSpec["containers"].([]interface{})

    for _, container := range containers {
        cont, _ := container.(map[string]interface{})
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        image, _ := cont["image"].(string)

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

    spec, _ := v.Manifest["spec"].(map[string]interface{})
    template, _ := spec["template"].(map[string]interface{})
    podSpec, _ := template["spec"].(map[string]interface{})
    containers, _ := podSpec["containers"].([]interface{})

    for _, container := range containers {
        cont, _ := container.(map[string]interface{})
        name, _ := cont["name"].(string)
        if name == "" {
            name = "unnamed"
        }
        ports, _ := cont["ports"].([]interface{})

        if v.Rules.Networking.PortsRequired && len(ports) == 0 {
            v.Warnings = append(v.Warnings, ValidationIssue{
                Type:    "Warning",
                Message: fmt.Sprintf("Container '%s' missing port definitions", name),
                Reason:  "Port definitions are required to expose the container to the network.",
                Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      containers:\n      - name: %s\n        ports:\n        - containerPort: 80  # Add port definitions", name),
            })
        }
        for _, port := range ports {
            p, _ := port.(map[string]interface{})
            containerPort, _ := p["containerPort"].(int)
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

    spec, _ := v.Manifest["spec"].(map[string]interface{})
    template, _ := spec["template"].(map[string]interface{})
    podSpec, _ := template["spec"].(map[string]interface{})
    containers, _ := podSpec["containers"].([]interface{})

    for _, container := range containers {
        cont, _ := container.(map[string]interface{})
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

    spec, _ := v.Manifest["spec"].(map[string]interface{})
    template, _ := spec["template"].(map[string]interface{})
    podSpec, _ := template["spec"].(map[string]interface{})
    volumes, _ := podSpec["volumes"].([]interface{})

    if v.Rules.Volumes.Required && len(volumes) == 0 {
        v.Warnings = append(v.Warnings, ValidationIssue{
            Type:    "Warning",
            Message: "Volumes are required but none defined",
            Reason:  "Volumes are required for persistent storage or configuration.",
            Fix:     fmt.Sprintf("spec:\n  template:\n    spec:\n      volumes:\n      - name: <volume-name>\n        configMap:\n          name: <configmap-name>  # Add a volume"),
        })
    }

    for _, volume := range volumes {
        vol, _ := volume.(map[string]interface{})
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

// Bubble Tea Model for Interactive UI
type model struct {
    validator    *Validator
    issues       []ValidationIssue
    currentIndex int
    quit         bool
}

func (m model) Init() tea.Cmd {
    return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "q", "ctrl+c":
            m.quit = true
            return m, tea.Quit
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
        return "Validation complete. Goodbye!\n"
    }

    if len(m.issues) == 0 {
        return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render("✓ Manifest looks good!\n")
    }

    var s strings.Builder
    s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")).Render(fmt.Sprintf("Validation Issues (%d/%d):\n", m.currentIndex+1, len(m.issues))))

    issue := m.issues[m.currentIndex]
    style := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
    if issue.Type == "Warning" {
        style = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
    }

    s.WriteString(style.Render(fmt.Sprintf("%s: %s\n", issue.Type, issue.Message)))
    s.WriteString(lipgloss.NewStyle().Render(fmt.Sprintf("Reason: %s\n", issue.Reason)))
    s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render(fmt.Sprintf("Fix:\n%s\n", issue.Fix)))

    s.WriteString("\nUse ↑/↓ or k/j to navigate, q to quit.\n")
    return s.String()
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

    var manifests []map[string]interface{}
    if err := yaml.Unmarshal(data, &manifests); err != nil {
        return fmt.Errorf("error parsing manifest: %v", err)
    }

    for _, manifest := range manifests {
        if manifest == nil {
            continue
        }

        validator := &Validator{
            Rules:    rules,
            Manifest: manifest,
            Kind:     strings.ToLower(manifest["kind"].(string)),
        }

        // Run all validation checks
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

        // Combine errors and warnings for display
        issues := append(validator.Errors, validator.Warnings...)
        if len(issues) == 0 {
            issues = []ValidationIssue{}
        }

        // Start the Bubble Tea UI
        p := tea.NewProgram(model{validator: validator, issues: issues})
        if _, err := p.Run(); err != nil {
            return fmt.Errorf("error running UI: %v", err)
        }
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