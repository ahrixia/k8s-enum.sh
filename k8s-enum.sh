#!/bin/bash

#=============================================================================
#  K8S-ENUM - Kubernetes Enumeration Tool (LinPEAS Style)
#  Author: Astik Rawat (ahrixia)
#  Usage: ./k8s-enum.sh --profile <kubeconfig-file>
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
NC='\033[0m' # No Color

# Highlight colors for findings
CRITICAL='\033[1;91m'    # Red Bold - Critical findings
HIGH='\033[0;91m'        # Red - High severity
MEDIUM='\033[0;93m'      # Yellow - Medium severity
LOW='\033[0;92m'         # Green - Low/Info
INFO='\033[0;96m'        # Cyan - Information

# Banner
print_banner() {
    echo -e "${GREEN}"
    cat << 'EOF'
    ██╗  ██╗ █████╗ ███████╗    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
    ██║ ██╔╝██╔══██╗██╔════╝    ██╔════╝████╗  ██║██║   ██║████╗ ████║
    █████╔╝ ╚█████╔╝███████╗    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
    ██╔═██╗ ██╔══██╗╚════██║    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
    ██║  ██╗╚█████╔╝███████║    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
    ╚═╝  ╚═╝ ╚════╝ ╚══════╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}    Kubernetes Enumeration Tool v${VERSION} by Ahrixia"
    echo -e "${CYAN}    For authorized security testing only${NC}"
    echo ""
}

# Section headers
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

print_command() {
    echo -e "${CYAN}    └─➤ CMD: ${WHITE}$1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# Usage
usage() {
    echo -e "${WHITE}Usage:${NC} $0 --profile <kubeconfig-file> [options]"
    echo ""
    echo -e "${WHITE}Options:${NC}"
    echo "  --profile, -p    Path to kubeconfig file (required)"
    echo "  --namespace, -n  Target namespace (default: current context namespace)"
    echo "  --all-ns         Enumerate all namespaces"
    echo "  --quick          Quick scan (skip slow checks)"
    echo "  --help, -h       Show this help message"
    echo ""
    echo -e "${WHITE}Examples:${NC}"
    echo "  $0 --profile ./kubeconfig.yaml"
    echo "  $0 --profile ./kubeconfig.yaml --namespace kube-system"
    echo "  $0 --profile ./kubeconfig.yaml --all-ns"
    exit 1
}

# Parse arguments
PROFILE=""
NAMESPACE=""
ALL_NS=false
QUICK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile|-p)
            PROFILE="$2"
            shift 2
            ;;
        --namespace|-n)
            NAMESPACE="$2"
            shift 2
            ;;
        --all-ns)
            ALL_NS=true
            shift
            ;;
        --quick)
            QUICK=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

if [ -z "$PROFILE" ]; then
    echo -e "${RED}Error: --profile is required${NC}"
    usage
fi

if [ ! -f "$PROFILE" ]; then
    echo -e "${RED}Error: Profile file '$PROFILE' not found${NC}"
    exit 1
fi

# kubectl wrapper
kctl() {
    kubectl --kubeconfig="$PROFILE" "$@" 2>/dev/null
}

kctl_raw() {
    kubectl --kubeconfig="$PROFILE" "$@"
}

# Main enumeration functions
check_connection() {
    print_section "CONNECTION CHECK"

    if kctl cluster-info &>/dev/null; then
        print_success "Connected to cluster"
        echo ""
        kctl cluster-info 2>/dev/null | head -5
    else
        print_error "Cannot connect to cluster"
        echo -e "${YELLOW}Attempting to get version...${NC}"
        kctl version --short 2>&1
    fi
}

get_current_context() {
    print_section "CURRENT IDENTITY"

    # Get current context
    local context=$(kctl config current-context 2>/dev/null)
    echo -e "${INFO}Current Context:${NC} $context"

    # Try to extract SA info from token
    local token=$(grep -A1 "token:" "$PROFILE" 2>/dev/null | tail -1 | tr -d ' ')
    if [ -n "$token" ]; then
        # Decode JWT payload
        local payload=$(echo "$token" | cut -d'.' -f2 | base64 -d 2>/dev/null)
        if [ -n "$payload" ]; then
            local sa_name=$(echo "$payload" | grep -o '"serviceaccount":{[^}]*"name":"[^"]*"' | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
            local sa_ns=$(echo "$payload" | grep -o '"namespace":"[^"]*"' | head -1 | cut -d'"' -f4)
            local sa_uid=$(echo "$payload" | grep -o '"serviceaccount":{[^}]*"uid":"[^"]*"' | grep -o '"uid":"[^"]*"' | cut -d'"' -f4)

            if [ -n "$sa_name" ]; then
                echo -e "${INFO}Service Account:${NC} ${GREEN}$sa_name${NC}"
                echo -e "${INFO}Namespace:${NC} ${GREEN}$sa_ns${NC}"
                echo -e "${INFO}Full Identity:${NC} system:serviceaccount:$sa_ns:$sa_name"
            fi
        fi
    fi
}

enumerate_permissions() {
    print_section "PERMISSION ENUMERATION"

    print_subsection "Current Permissions (auth can-i --list)"

    local perms=$(kctl auth can-i --list 2>/dev/null)
    echo "$perms"

    # Analyze dangerous permissions
    echo ""
    print_subsection "Permission Analysis"

    # Check for critical permissions
    if echo "$perms" | grep -q "pods/exec.*create"; then
        print_finding "CRITICAL" "Can CREATE pods/exec - Remote Code Execution possible!"
        print_tip "Execute commands in pods to pivot or extract secrets"
        print_command "kubectl exec -it <pod-name> -- /bin/sh"
    fi

    if echo "$perms" | grep -q "secrets.*get\|secrets.*list"; then
        print_finding "CRITICAL" "Can GET/LIST secrets - Credential extraction possible!"
        print_tip "Extract secrets from accessible namespaces"
        print_command "kubectl get secrets -o yaml"
    fi

    if echo "$perms" | grep -q "pods.*create"; then
        print_finding "CRITICAL" "Can CREATE pods - Container escape possible!"
        print_tip "Create privileged pod to escape to node"
        print_command "kubectl run pwned --image=alpine --restart=Never -it --rm -- /bin/sh"
    fi

    if echo "$perms" | grep -qE "serviceaccounts.*impersonate|users.*impersonate"; then
        print_finding "CRITICAL" "Can IMPERSONATE - Privilege escalation possible!"
        print_tip "Impersonate other service accounts for elevated access"
        print_command "kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>"
    fi

    if echo "$perms" | grep -q "cronjobs.*create\|jobs.*create"; then
        print_finding "HIGH" "Can CREATE cronjobs/jobs - Persistence possible!"
        print_tip "Create cronjob with different service account"
    fi

    if echo "$perms" | grep -q "daemonsets.*create"; then
        print_finding "HIGH" "Can CREATE daemonsets - Cluster-wide execution possible!"
        print_tip "Deploy daemonset to run on all nodes"
    fi

    if echo "$perms" | grep -q "rolebindings.*create\|clusterrolebindings.*create"; then
        print_finding "CRITICAL" "Can CREATE rolebindings - Privilege escalation possible!"
        print_tip "Bind cluster-admin role to your service account"
    fi

    if echo "$perms" | grep -q "serviceaccounts/token.*create"; then
        print_finding "HIGH" "Can CREATE serviceaccount tokens - Token generation possible!"
        print_tip "Generate tokens for other service accounts"
    fi

    # Check for specific resource impersonation
    if echo "$perms" | grep -q "impersonate"; then
        local impersonate_targets=$(echo "$perms" | grep "impersonate" | awk '{print $3}')
        if [ -n "$impersonate_targets" ] && [ "$impersonate_targets" != "[]" ]; then
            print_finding "CRITICAL" "Can impersonate specific targets: $impersonate_targets"
            print_tip "Use --as flag to impersonate these identities"
            print_command "kubectl auth can-i --list --as=system:serviceaccount:<ns>:<target>"
        fi
    fi
}

enumerate_namespaces() {
    print_section "NAMESPACE ENUMERATION"

    local namespaces=$(kctl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

    if [ -n "$namespaces" ]; then
        print_success "Can list namespaces"
        echo ""
        for ns in $namespaces; do
            if [[ "$ns" == "kube-system" || "$ns" == "kube-public" || "$ns" == "default" ]]; then
                echo -e "  ${YELLOW}• $ns${NC} (system namespace)"
            else
                echo -e "  ${GREEN}• $ns${NC}"
            fi
        done
        print_tip "Check permissions in each namespace"
        print_command "kubectl auth can-i --list -n <namespace>"
    else
        print_error "Cannot list namespaces"
        print_tip "Try common namespace names: default, kube-system, kube-public"
    fi
}

enumerate_pods() {
    print_section "POD ENUMERATION"

    local ns_flag=""
    if [ "$ALL_NS" = true ]; then
        ns_flag="--all-namespaces"
    elif [ -n "$NAMESPACE" ]; then
        ns_flag="-n $NAMESPACE"
    fi

    local pods=$(kctl get pods $ns_flag -o wide 2>/dev/null)

    if [ -n "$pods" ]; then
        print_success "Can list pods"
        echo ""
        echo "$pods"

        # Check for interesting pods
        print_subsection "Interesting Pods Analysis"

        # Check for pods with hostNetwork/hostPID/hostIPC
        local privileged_pods=$(kctl get pods $ns_flag -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.namespace}{"\t"}{.spec.hostNetwork}{"\t"}{.spec.hostPID}{"\n"}{end}' 2>/dev/null | grep -E "true")
        if [ -n "$privileged_pods" ]; then
            print_finding "HIGH" "Pods with host namespace access found:"
            echo "$privileged_pods"
            print_tip "These pods may allow node access"
        fi

        # List service accounts used by pods
        print_subsection "Service Accounts in Pods"
        kctl get pods $ns_flag -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}' 2>/dev/null | column -t

    else
        print_error "Cannot list pods"
    fi
}

enumerate_services() {
    print_section "SERVICE ENUMERATION"

    local ns_flag=""
    if [ "$ALL_NS" = true ]; then
        ns_flag="--all-namespaces"
    elif [ -n "$NAMESPACE" ]; then
        ns_flag="-n $NAMESPACE"
    fi

    local services=$(kctl get services $ns_flag -o wide 2>/dev/null)

    if [ -n "$services" ]; then
        print_success "Can list services"
        echo ""
        echo "$services"

        # Check for NodePort services
        print_subsection "Exposed Services (NodePort/LoadBalancer)"
        kctl get services $ns_flag -o jsonpath='{range .items[?(@.spec.type!="ClusterIP")]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.type}{"\t"}{.spec.ports[*].nodePort}{"\n"}{end}' 2>/dev/null

        if kctl get services $ns_flag 2>/dev/null | grep -qE "NodePort|LoadBalancer"; then
            print_finding "MEDIUM" "Exposed services found - potential attack surface"
            print_tip "Check if these services expose sensitive functionality"
        fi
    else
        print_error "Cannot list services"
    fi
}

enumerate_secrets() {
    print_section "SECRET ENUMERATION"

    local ns_flag=""
    if [ "$ALL_NS" = true ]; then
        ns_flag="--all-namespaces"
    elif [ -n "$NAMESPACE" ]; then
        ns_flag="-n $NAMESPACE"
    fi

    local secrets=$(kctl get secrets $ns_flag 2>/dev/null)

    if [ -n "$secrets" ]; then
        print_finding "CRITICAL" "Can list secrets!"
        echo ""
        echo "$secrets"

        print_tip "Extract secret values with:"
        print_command "kubectl get secret <name> -o yaml"
        print_command "kubectl get secret <name> -o jsonpath='{.data}' | base64 -d"

        # Check for interesting secret types
        print_subsection "Interesting Secrets"

        if echo "$secrets" | grep -q "kubernetes.io/service-account-token"; then
            print_finding "HIGH" "Service account tokens found - can be used for lateral movement"
        fi

        if echo "$secrets" | grep -qiE "docker|registry|pull"; then
            print_finding "MEDIUM" "Docker registry secrets found - may contain registry credentials"
        fi

        if echo "$secrets" | grep -qiE "tls|cert|ssl"; then
            print_finding "MEDIUM" "TLS secrets found - may contain private keys"
        fi

    else
        print_error "Cannot list secrets"
        print_tip "Try specific namespaces or impersonation"
    fi
}

enumerate_serviceaccounts() {
    print_section "SERVICE ACCOUNT ENUMERATION"

    local ns_flag=""
    if [ "$ALL_NS" = true ]; then
        ns_flag="--all-namespaces"
    elif [ -n "$NAMESPACE" ]; then
        ns_flag="-n $NAMESPACE"
    fi

    local sas=$(kctl get serviceaccounts $ns_flag 2>/dev/null)

    if [ -n "$sas" ]; then
        print_success "Can list service accounts"
        echo ""
        echo "$sas"

        print_tip "Check what each service account can do:"
        print_command "kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>"
    else
        print_error "Cannot list service accounts"
    fi
}

enumerate_roles() {
    print_section "RBAC ENUMERATION"

    print_subsection "Roles"
    local roles=$(kctl get roles --all-namespaces 2>/dev/null)
    if [ -n "$roles" ]; then
        echo "$roles"
    else
        print_error "Cannot list roles"
    fi

    print_subsection "ClusterRoles"
    local clusterroles=$(kctl get clusterroles 2>/dev/null)
    if [ -n "$clusterroles" ]; then
        echo "$clusterroles" | head -30
        echo -e "${YELLOW}(truncated - use kubectl get clusterroles for full list)${NC}"
    else
        print_error "Cannot list clusterroles"
    fi

    print_subsection "RoleBindings"
    local rolebindings=$(kctl get rolebindings --all-namespaces 2>/dev/null)
    if [ -n "$rolebindings" ]; then
        echo "$rolebindings"
    else
        print_error "Cannot list rolebindings"
    fi

    print_subsection "ClusterRoleBindings"
    local clusterrolebindings=$(kctl get clusterrolebindings 2>/dev/null)
    if [ -n "$clusterrolebindings" ]; then
        echo "$clusterrolebindings" | head -30
    else
        print_error "Cannot list clusterrolebindings"
    fi
}

enumerate_cronjobs() {
    print_section "CRONJOB ENUMERATION"

    local ns_flag=""
    if [ "$ALL_NS" = true ]; then
        ns_flag="--all-namespaces"
    elif [ -n "$NAMESPACE" ]; then
        ns_flag="-n $NAMESPACE"
    fi

    local cronjobs=$(kctl get cronjobs $ns_flag 2>/dev/null)

    if [ -n "$cronjobs" ]; then
        print_success "Can list cronjobs"
        echo ""
        echo "$cronjobs"

        print_tip "CronJobs may run with different service accounts - check for privilege escalation"
        print_command "kubectl get cronjob <name> -o yaml | grep serviceAccount"

        # Get SA for each cronjob
        print_subsection "CronJob Service Accounts"
        kctl get cronjobs $ns_flag -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.jobTemplate.spec.template.spec.serviceAccountName}{"\n"}{end}' 2>/dev/null | column -t

    else
        print_error "Cannot list cronjobs"
    fi
}

check_impersonation() {
    print_section "IMPERSONATION CHECK"

    # Check if we can impersonate
    local can_impersonate=$(kctl auth can-i impersonate serviceaccounts 2>/dev/null)

    if [ "$can_impersonate" = "yes" ]; then
        print_finding "CRITICAL" "Can impersonate service accounts cluster-wide!"
        print_tip "Enumerate permissions of other service accounts"
    fi

    # Check for specific impersonation targets in permissions
    local perms=$(kctl auth can-i --list 2>/dev/null)
    local impersonate_line=$(echo "$perms" | grep "impersonate")

    if [ -n "$impersonate_line" ]; then
        local targets=$(echo "$impersonate_line" | awk '{print $3}')
        if [ -n "$targets" ] && [ "$targets" != "[]" ]; then
            print_finding "CRITICAL" "Can impersonate specific targets: $targets"

            # Try to get what impersonated user can do
            for target in $(echo "$targets" | tr -d '[]' | tr ',' ' '); do
                echo ""
                echo -e "${CYAN}Checking permissions as: $target${NC}"

                # Try different namespace formats
                for ns in "mirror-world" "zion" "default" "kube-system"; do
                    local as_flag="--as=system:serviceaccount:$ns:$target"
                    local impersonated_perms=$(kctl auth can-i --list $as_flag 2>/dev/null | head -30)
                    if [ -n "$impersonated_perms" ] && ! echo "$impersonated_perms" | grep -q "Forbidden"; then
                        echo -e "${GREEN}As system:serviceaccount:$ns:$target:${NC}"
                        echo "$impersonated_perms"
                        break
                    fi
                done
            done
        fi
    fi
}

check_token_mounts() {
    print_section "TOKEN MOUNT CHECK"

    print_subsection "Pods with Service Account Tokens"

    local ns_flag=""
    if [ "$ALL_NS" = true ]; then
        ns_flag="--all-namespaces"
    elif [ -n "$NAMESPACE" ]; then
        ns_flag="-n $NAMESPACE"
    fi

    # Check if pods have automountServiceAccountToken
    kctl get pods $ns_flag -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.automountServiceAccountToken}{"\n"}{end}' 2>/dev/null | \
        while read line; do
            if echo "$line" | grep -q "false"; then
                echo -e "${GREEN}$line${NC} (token not mounted)"
            else
                echo -e "${YELLOW}$line${NC} (token mounted - default)"
            fi
        done

    print_tip "If you can exec into pods, extract tokens from /var/run/secrets/kubernetes.io/serviceaccount/"
}

enumerate_configmaps() {
    print_section "CONFIGMAP ENUMERATION"

    local ns_flag=""
    if [ "$ALL_NS" = true ]; then
        ns_flag="--all-namespaces"
    elif [ -n "$NAMESPACE" ]; then
        ns_flag="-n $NAMESPACE"
    fi

    local cms=$(kctl get configmaps $ns_flag 2>/dev/null)

    if [ -n "$cms" ]; then
        print_success "Can list configmaps"
        echo ""
        echo "$cms"

        print_tip "ConfigMaps may contain sensitive configuration"
        print_command "kubectl get configmap <name> -o yaml"
    else
        print_error "Cannot list configmaps"
    fi
}

check_api_resources() {
    print_section "API RESOURCES CHECK"

    echo -e "${INFO}Checking accessible API resources...${NC}"

    local resources=$(kctl api-resources --verbs=list -o name 2>/dev/null)

    if [ -n "$resources" ]; then
        echo ""
        for resource in $resources; do
            if kctl get $resource --all-namespaces &>/dev/null; then
                echo -e "${GREEN}[✓] Can list: $resource${NC}"
            fi
        done 2>/dev/null | head -50
    fi
}

generate_report() {
    print_section "SUMMARY & RECOMMENDATIONS"

    echo -e "${BOLD}Based on enumeration, here are the recommended next steps:${NC}"
    echo ""

    local perms=$(kctl auth can-i --list 2>/dev/null)

    # Priority actions based on permissions
    local priority=1

    if echo "$perms" | grep -q "impersonate"; then
        echo -e "${CRITICAL}[$priority] IMPERSONATION AVAILABLE${NC}"
        echo "    Use impersonation to escalate privileges"
        echo "    kubectl auth can-i --list --as=system:serviceaccount:<ns>:<target>"
        ((priority++))
    fi

    if echo "$perms" | grep -q "pods/exec.*create"; then
        echo -e "${CRITICAL}[$priority] POD EXEC AVAILABLE${NC}"
        echo "    Execute into pods to extract tokens and pivot"
        echo "    kubectl exec -it <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
        ((priority++))
    fi

    if echo "$perms" | grep -q "secrets.*get\|secrets.*list"; then
        echo -e "${CRITICAL}[$priority] SECRET ACCESS AVAILABLE${NC}"
        echo "    Extract secrets for credentials"
        echo "    kubectl get secrets -o yaml"
        ((priority++))
    fi

    if echo "$perms" | grep -q "pods.*create"; then
        echo -e "${HIGH}[$priority] POD CREATION AVAILABLE${NC}"
        echo "    Create privileged pod for node access"
        ((priority++))
    fi

    if echo "$perms" | grep -q "cronjobs.*get\|cronjobs.*list"; then
        echo -e "${MEDIUM}[$priority] CRONJOB ACCESS AVAILABLE${NC}"
        echo "    Check cronjobs for privileged service accounts"
        echo "    kubectl get cronjob -o yaml | grep serviceAccount"
        ((priority++))
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    Enumeration Complete                           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
}

# Main execution
main() {
    print_banner

    echo -e "${WHITE}Profile:${NC} $PROFILE"
    [ -n "$NAMESPACE" ] && echo -e "${WHITE}Namespace:${NC} $NAMESPACE"
    [ "$ALL_NS" = true ] && echo -e "${WHITE}Mode:${NC} All Namespaces"
    echo ""

    check_connection
    get_current_context
    enumerate_permissions
    enumerate_namespaces
    enumerate_pods
    enumerate_services
    enumerate_secrets
    enumerate_serviceaccounts
    enumerate_cronjobs
    enumerate_configmaps

    if [ "$QUICK" = false ]; then
        enumerate_roles
        check_impersonation
        check_token_mounts
    fi

    generate_report
}

main
