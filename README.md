# Kubetector - K8s-Validator (Go)

![](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)

![](https://img.shields.io/badge/License-MIT-blue.svg)

## Overview

`k8s-validator` is a command-line tool written in Go designed to validate Kubernetes manifests against a set of organizational rules. It ensures that your Kubernetes YAML files adhere to best practices and organizational standards, helping to catch potential issues before deployment. The tool provides a polished, interactive terminal UI to display validation issues, making it easy to review errors and warnings and apply suggested fixes.

### Purpose

The primary purpose of `k8s-validator` is to enforce consistency and compliance in Kubernetes manifests. It checks for:

- Required fields in manifests (e.g., `apiVersion`, `kind`, `metadata`).
- Namespace requirements (e.g., disallowing the `default` namespace).
- Label and annotation compliance (e.g., ensuring specific labels like `environment` are set to allowed values such as `dev`, `test`, or `prod`).
- Resource requests and limits (e.g., ensuring CPU and memory requests meet minimum requirements).
- Security context settings (e.g., ensuring containers don’t run as privileged).
- Image policies (e.g., enforcing a specific registry or disallowing the `latest` tag).
- Networking rules (e.g., ensuring only allowed ports are used).
- Probes and volume configurations.

The tool is particularly useful for DevOps teams, SREs, and developers who want to automate the validation of Kubernetes manifests as part of their CI/CD pipelines or local development workflows.

### Current State

As of now, `k8s-validator` is a Go-based CLI tool that can be run using `go run`. It does not yet produce a compiled binary for distribution, but it’s fully functional for local use. The tool reads a `validation_rules.yaml` file to define the rules and validates a specified Kubernetes manifest (e.g., `test.yaml`) against these rules, displaying results in an interactive terminal UI.

---

## Features

- **Interactive Terminal UI**: Built with `charmbracelet/bubbletea` and styled with `lipgloss`, the UI provides a pleasant experience with color-coded errors/warnings, a progress bar, and navigation instructions.
- **Customizable Rules**: Define your organization’s standards in `validation_rules.yaml` to enforce specific requirements for labels, annotations, resources, security, and more.
- **Detailed Feedback**: Each validation issue includes a type (Error/Warning), message, reason, and a suggested fix with a properly formatted YAML snippet.
- **Cross-Referencing**: Supports validating relationships between manifests (e.g., ensuring a `Deployment` has a corresponding `Service`).
- **No Dependencies for End Users**: Once compiled (in the future), the tool will be a single binary with no external dependencies, making it easy to distribute and run.

---

## Prerequisites

To use `k8s-validator`, you need the following:

- **Go**: Version 1.22 or higher. Install it from [golang.org](https://golang.org/dl/).
- **Git**: To clone the repository.
- A Kubernetes manifest file (e.g., `test.yaml`) to validate.
- A `validation_rules.yaml` file defining your validation rules.

---

## Installation

Since we’re not yet distributing a binary, you’ll need to run the tool directly from the source code using `go run`. Follow these steps to set up the project:

1. **Clone the Repository**:
    
    ```bash
    git clone <https://github.com/yourusername/kubetector.git>
    cd kubetector/go
    
    ```
    
2. **Install Dependencies**:
The tool uses several Go modules. Install them with:
    
    ```bash
    go get github.com/charmbracelet/bubbletea
    go get github.com/charmbracelet/lipgloss
    go get github.com/spf13/cobra
    go get gopkg.in/yaml.v3
    go mod tidy
    
    ```
    
3. **Verify Setup**:
Ensure the following files are in the `kubetector` directory:
    - `go/k8s-validator.go`: The main Go source file.
    - `validation_rules.yaml`: The rules file (see [Customization](https://www.notion.so/1c3271f715f4801a96faf2118816ade1?pvs=21) for details).
    - `test.yaml`: A sample Kubernetes manifest to validate (or your own manifest).

---

## Usage

### Running the Tool

To validate a Kubernetes manifest, run the tool with the path to your manifest file:

```bash
go run k8s-validator.go ../test.yaml

```

- `../test.yaml`: The path to the Kubernetes manifest file you want to validate. The path is relative to the `go` directory, so `../test.yaml` assumes the file is in the parent directory (`kubetector`).
- You can also specify a directory containing multiple manifests as a second argument (optional):
This allows the tool to cross-reference other manifests (e.g., to check for a corresponding `Service` for a `Deployment`).
    
    ```bash
    go run k8s-validator.go ../test.yaml ../manifests
    
    ```
    

### Interacting with the UI

Once the tool runs, it will display an interactive terminal UI:

- **Header**: Shows the current issue number and total issues (e.g., "Validation Issues (1/14)").
- **Issue Details**:
    - **Type**: "Error" (in red) or "Warning" (in yellow).
    - **Message**: A brief description of the issue (e.g., "Container 'app-container' securityContext.privileged must be false, got true").
    - **Reason**: Explains why the issue is a problem.
    - **Fix**: Provides a YAML snippet to resolve the issue, properly indented for easy copy-pasting.
- **Progress Bar**: A visual indicator of your progress through the issues.
- **Navigation**: Use the following keys:
    - `↑` or `k`: Move to the previous issue.
    - `↓` or `j`: Move to the next issue.
    - `q` or `Ctrl+C`: Quit the tool.

### Example Output

If your `test.yaml` has an issue, the UI might look like this:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Validation Issues (1/14)                                                     │
│                                                                              │
│ Error Container 'app-container' securityContext.privileged must be false, got true
│ Reason: The container-level security context setting 'privileged' must be false for security compliance.
│                                                                              │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │ spec:                                                                    │ │
│ │   template:                                                              │ │
│ │     spec:                                                                │ │
│ │       containers:                                                        │ │
│ │       - name: app-container                                              │ │
│ │         securityContext:                                                 │ │
│ │           privileged: false  # Set the correct value                     │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
│ [██████████                                        ]                      │
│ Use ↑/↓ or k/j to navigate, q to quit.                                       │
└──────────────────────────────────────────────────────────────────────────────┘

```

---

## Customization

The validation rules are defined in `validation_rules.yaml`, located in the `kubetector` directory. You can customize these rules to meet your organization’s specific needs.

### Structure of `validation_rules.yaml`

The `validation_rules.yaml` file defines the rules for validating Kubernetes manifests. Here’s an overview of the sections and how to customize them:

### Required Fields

Defines the required fields for each Kubernetes resource kind (e.g., `Deployment`, `Service`).

```yaml
required_fields:
  deployment:
    - apiVersion
    - kind
    - metadata
    - spec
    - spec.replicas
    - spec.template.spec.containers
  service:
    - apiVersion
    - kind
    - metadata
    - spec

```

- **Customization**: Add or remove fields for each kind. For example, to require `spec.strategy` for `Deployment`, add it to the list:
    
    ```yaml
    required_fields:
      deployment:
        - apiVersion
        - kind
        - metadata
        - spec
        - spec.replicas
        - spec.strategy
        - spec.template.spec.containers
    
    ```
    

### Namespace Rules

Enforces namespace requirements.

```yaml
namespace:
  required: true

```

- **Customization**: Set `required: false` to allow manifests without a namespace. The tool will still warn if the namespace is `default`.

### Label Requirements

Enforces rules for labels in the `metadata.labels` section.

```yaml
labels:
  app:
    required: true
  environment:
    required: true
    allowed_values:
      - dev
      - test
      - prod
  team:
    required: true
    value: "devops"

```

- **Customization**:
    - Add new labels by adding entries under `labels`.
    - Use `required: true` to make a label mandatory.
    - Use `allowed_values` to specify a list of acceptable values (e.g., `["dev", "test", "prod"]` for `environment`).
    - Use `value` to enforce a single value (e.g., `"devops"` for `team`).
    - Example: To add a `region` label that must be either `us-east` or `eu-west`:
        
        ```yaml
        labels:
          app:
            required: true
          environment:
            required: true
            allowed_values:
              - dev
              - test
              - prod
          team:
            required: true
            value: "devops"
          region:
            required: true
            allowed_values:
              - us-east
              - eu-west
        
        ```
        

### Annotation Requirements

Enforces rules for annotations in the `metadata.annotations` section.

```yaml
annotations:
  owner:
    required: true
    value: "devops-team"
  monitored:
    required: true
    value: "true"

```

- **Customization**: Add new annotations or modify existing ones. For example, to require an `app-version` annotation:
    
    ```yaml
    annotations:
      owner:
        required: true
        value: "devops-team"
      monitored:
        required: true
        value: "true"
      app-version:
        required: true
        value: "1.0.0"
    
    ```
    

### Resource Requirements

Enforces resource requests and limits for containers.

```yaml
resources:
  requests:
    memory:
      required: true
      min: "256Mi"
    cpu:
      required: true
      min: "100m"
  limits:
    memory:
      required: true
      max: "1Gi"
    cpu:
      required: true
      max: "500m"

```

- **Customization**: Adjust the `min` and `max` values, or add new resources (e.g., `ephemeral-storage`):
    
    ```yaml
    resources:
      requests:
        memory:
          required: true
          min: "512Mi"
        cpu:
          required: true
          min: "200m"
        ephemeral-storage:
          required: true
          min: "1Gi"
      limits:
        memory:
          required: true
          max: "2Gi"
        cpu:
          required: true
          max: "1"
    
    ```
    

### Security Context Rules

Enforces security context settings at the pod and container levels.

```yaml
security:
  pod:
    runAsNonRoot:
      required: true
      value: true
  container:
    privileged:
      required: true
      value: false
    readOnlyRootFilesystem:
      required: true
      value: true

```

- **Customization**: Add new security settings or modify existing ones. For example, to require `allowPrivilegeEscalation: false` for containers:
    
    ```yaml
    security:
      pod:
        runAsNonRoot:
          required: true
          value: true
      container:
        privileged:
          required: true
          value: false
        readOnlyRootFilesystem:
          required: true
          value: true
        allowPrivilegeEscalation:
          required: true
          value: false
    
    ```
    

### Service Relationship

Ensures a `Deployment` has a corresponding `Service`.

```yaml
require_service: true

```

- **Customization**: Set `require_service: false` to disable this check.

### Image Policies

Enforces rules for container images.

```yaml
images:
  registry: "myregistry.com/"
  no_latest: true
  allowed:
    - "myregistry.com/app:1.0.0"
    - "myregistry.com/db:2.3.1"

```

- **Customization**:
    - Change `registry` to your organization’s registry.
    - Set `no_latest: false` to allow the `latest` tag.
    - Update the `allowed` list with your approved images.

### Networking Rules

Enforces networking rules for container ports.

```yaml
networking:
  ports_required: true
  allowed_ports:
    - 80
    - 443
    - 8080

```

- **Customization**:
    - Set `ports_required: false` to allow containers without ports.
    - Update `allowed_ports` to include your organization’s allowed ports.

### Probe Requirements

Enforces liveness and readiness probes for containers.

```yaml
probes:
  liveness_required: true
  readiness_required: true

```

- **Customization**: Set `liveness_required: false` or `readiness_required: false` to make these probes optional.

### Volume Rules

Enforces rules for volumes.

```yaml
volumes:
  required: false
  allowed_types:
    - persistentVolumeClaim
    - configMap
    - secret

```

- **Customization**:
    - Set `required: true` to require volumes.
    - Update `allowed_types` to include your allowed volume types.

---

## Project Structure

The project is organized as follows:

```
kubetector/
├── go/
│   ├── k8s-validator.go  # Main Go source file
│   ├── go.mod            # Go module file
│   └── go.sum            # Go module checksums
├── validation_rules.yaml # Validation rules
├── test.yaml             # Sample Kubernetes manifest
└── README.md             # This documentation

```

- `go/k8s-validator.go`: The main Go source file containing the validation logic and UI.
- `validation_rules.yaml`: Defines the rules for validation.
- `test.yaml`: A sample Kubernetes manifest for testing.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix:
    
    ```bash
    git checkout -b feature/your-feature-name
    
    ```
    
3. Make your changes and test them:
    
    ```bash
    go run k8s-validator.go ../test.yaml
    
    ```
    
4. Commit your changes and push to your fork:
    
    ```bash
    git commit -m "Add your feature description"
    git push origin feature/your-feature-name
    
    ```
    
5. Open a pull request with a detailed description of your changes.

### Adding New Validation Rules

To add a new validation rule:

1. Update `validation_rules.yaml` with the new rule (see [Customization](https://www.notion.so/1c3271f715f4801a96faf2118816ade1?pvs=21)).
2. Modify `k8s-validator.go` to add a new validation method (e.g., `checkNewRule`) in the `Validator` struct.
3. Call the new method in `validateManifest`:
    
    ```go
    validator.checkNewRule()
    
    ```
    
4. Test your changes with a sample manifest.

---

## Future Improvements

- **Binary Distribution**: Compile the tool into a single binary for easy distribution across platforms (e.g., Linux, macOS, Windows).
- **Additional Validation Rules**: Add more checks, such as validating pod affinity/anti-affinity, tolerations, or node selectors.
- **Output Formats**: Support additional output formats (e.g., JSON, plain text) for integration with CI/CD pipelines.
- **Rule Overrides**: Allow command-line flags to override specific rules for more flexibility.

---

## License

This project is licensed under the MIT License. 

---

## Contact

For questions, issues, or suggestions, please open an issue on the [GitHub repository](https://github.com/bgcodehub/kubetector/issues).

---