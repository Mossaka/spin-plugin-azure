package aks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/spinframework/spin-plugin-azure/internal/pkg/config"
)

func runSpinner(prefix string) chan struct{} {
	done := make(chan struct{})
	spinner := []string{"|", "/", "-", "\\"}
	i := 0

	fmt.Printf("\r%s %s", prefix, spinner[0])

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				i = (i + 1) % len(spinner)
				fmt.Printf("\r%s %s", prefix, spinner[i])
			case <-done:
				fmt.Printf("\r%s Done!\n", prefix)
				return
			}
		}
	}()

	return done
}

// Service provides operations for Azure Kubernetes Service (AKS)
type Service struct {
	credential     azcore.TokenCredential
	subscriptionID string
}

// NewService creates a new AKS service
func NewService(credential azcore.TokenCredential, subscriptionID string) (*Service, error) {
	return &Service{
		credential:     credential,
		subscriptionID: subscriptionID,
	}, nil
}

// CreateCluster creates a new AKS cluster with workload identity enabled
func (s *Service) CreateCluster(ctx context.Context, resourceGroup, clusterName, location string, nodeCount int, nodeVMSize string, additionalArgs ...string) error {
	args := []string{
		"aks", "create",
		"--resource-group", resourceGroup,
		"--name", clusterName,
		"--location", location,
		"--enable-oidc-issuer",
		"--enable-workload-identity",
		"--generate-ssh-keys",
		"--node-count", fmt.Sprintf("%d", nodeCount),
		"--node-vm-size", nodeVMSize,
		"--dns-name-prefix", fmt.Sprintf("%s-wid", clusterName),
		"--subscription", s.subscriptionID,
	}

	args = append(args, additionalArgs...)

	fmt.Println("Creating AKS cluster with args:", strings.Join(args, " "))
	spinnerDone := runSpinner("creating AKS cluster...")

	cmd := exec.Command("az", args...)
	output, err := cmd.CombinedOutput()

	close(spinnerDone)

	if err != nil {
		return fmt.Errorf("failed to create AKS cluster: %w\nOutput: %s", err, string(output))
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg.ClusterName = clusterName
	cfg.ResourceGroup = resourceGroup

	if err := config.SaveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

// GetCluster gets an existing AKS cluster
func (s *Service) GetCluster(ctx context.Context, resourceGroup, clusterName string) error {
	cmd := exec.Command(
		"az", "aks", "show",
		"--resource-group", resourceGroup,
		"--name", clusterName,
		"--subscription", s.subscriptionID,
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get AKS cluster: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// UseCluster sets the current cluster in the configuration
func (s *Service) UseCluster(ctx context.Context, resourceGroup, clusterName string) error {
	if err := s.GetCluster(ctx, resourceGroup, clusterName); err != nil {
		return err
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg.ClusterName = clusterName
	cfg.ResourceGroup = resourceGroup

	if err := config.SaveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

// CheckWorkloadIdentity checks if workload identity is enabled on the current cluster
func (s *Service) CheckWorkloadIdentity(ctx context.Context) (bool, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return false, fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ClusterName == "" || cfg.ResourceGroup == "" {
		return false, fmt.Errorf("no cluster is currently selected, use 'spin azure cluster use' first")
	}

	cmd := exec.Command(
		"az", "aks", "show",
		"--resource-group", cfg.ResourceGroup,
		"--name", cfg.ClusterName,
		"--subscription", s.subscriptionID,
		"--query", "securityProfile.workloadIdentity.enabled",
		"--output", "tsv",
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check workload identity: %w\nOutput: %s", err, string(output))
	}

	result := strings.TrimSpace(string(output))
	return result == "true", nil
}

// EnableWorkloadIdentity enables workload identity on the current cluster
func (s *Service) EnableWorkloadIdentity(ctx context.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ClusterName == "" || cfg.ResourceGroup == "" {
		return fmt.Errorf("no cluster is currently selected, use 'spin azure cluster use' first")
	}

	cmd := exec.Command(
		"az", "aks", "update",
		"--resource-group", cfg.ResourceGroup,
		"--name", cfg.ClusterName,
		"--subscription", s.subscriptionID,
		"--enable-oidc-issuer",
		"--enable-workload-identity",
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable workload identity: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// DeploySpinOperator deploys the Spin Operator to the current Kubernetes cluster
func (s *Service) DeploySpinOperator(ctx context.Context) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ClusterName == "" || cfg.ResourceGroup == "" {
		return fmt.Errorf("no cluster is currently selected, use 'spin azure cluster use' first")
	}

	fmt.Println("Setting up kubectl with cluster credentials...")
	getCredsCmd := exec.Command(
		"az", "aks", "get-credentials",
		"--name", cfg.ClusterName,
		"--resource-group", cfg.ResourceGroup,
		"--subscription", s.subscriptionID,
		"--overwrite-existing",
	)

	fmt.Println("Executing command:", strings.Join(getCredsCmd.Args, " "))

	output, err := getCredsCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get Kubernetes credentials: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Installing Spin Operator Custom Resource Definitions...")
	crdsCmd := exec.Command(
		"kubectl", "apply", "-f",
		"https://github.com/spinframework/spin-operator/releases/download/v0.5.0/spin-operator.crds.yaml",
	)

	output, err = crdsCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install Spin Operator CRDs: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Installing Spin Operator Runtime Class...")
	runtimeClassCmd := exec.Command(
		"kubectl", "apply", "-f",
		"https://github.com/spinframework/spin-operator/releases/download/v0.5.0/spin-operator.runtime-class.yaml",
	)

	output, err = runtimeClassCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install Spin Operator Runtime Class: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Installing cert-manager CRDs...")
	certManagerCrdsCmd := exec.Command(
		"kubectl", "apply", "-f",
		"https://github.com/cert-manager/cert-manager/releases/download/v1.14.3/cert-manager.crds.yaml",
	)

	output, err = certManagerCrdsCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install cert-manager CRDs: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Adding Jetstack Helm repository...")
	addJetstackRepoCmd := exec.Command(
		"helm", "repo", "add", "jetstack", "https://charts.jetstack.io",
	)

	output, err = addJetstackRepoCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add Jetstack Helm repository: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Updating Helm repositories...")
	updateHelmRepoCmd := exec.Command(
		"helm", "repo", "update",
	)

	output, err = updateHelmRepoCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update Helm repositories: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Installing cert-manager...")
	installCertManagerCmd := exec.Command(
		"helm", "install", "cert-manager", "jetstack/cert-manager",
		"--namespace", "cert-manager",
		"--create-namespace",
		"--version", "v1.14.3",
	)

	output, err = installCertManagerCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install cert-manager: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Adding KWasm Helm repository...")
	addKwasmRepoCmd := exec.Command(
		"helm", "repo", "add", "kwasm", "http://kwasm.sh/kwasm-operator/",
	)

	output, err = addKwasmRepoCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add KWasm Helm repository: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Installing KWasm operator...")
	installKwasmCmd := exec.Command(
		"helm", "install", "kwasm-operator", "kwasm/kwasm-operator",
		"--namespace", "kwasm",
		"--create-namespace",
		"--set", "kwasmOperator.installerImage=ghcr.io/spinkube/containerd-shim-spin/node-installer:v0.18.0",
	)

	output, err = installKwasmCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install KWasm operator: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Provisioning nodes with KWasm...")
	annotateNodesCmd := exec.Command(
		"kubectl", "annotate", "node", "--all", "kwasm.sh/kwasm-node=true",
	)

	output, err = annotateNodesCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to annotate nodes for KWasm: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Waiting for KWasm operator to initialize nodes...")
	waitCmd := exec.Command(
		"sleep", "30",
	)

	_, err = waitCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed while waiting for KWasm initialization: %w", err)
	}

	fmt.Println("Installing Spin Operator...")
	installSpinOpCmd := exec.Command(
		"helm", "install", "spin-operator",
		"--namespace", "spin-operator",
		"--create-namespace",
		"--version", "0.5.0",
		"--wait",
		"oci://ghcr.io/spinframework/charts/spin-operator",
	)

	output, err = installSpinOpCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install Spin Operator: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("Applying shim executor configuration...")
	shimExecutorCmd := exec.Command(
		"kubectl", "apply", "-f",
		"https://github.com/spinframework/spin-operator/releases/download/v0.5.0/spin-operator.shim-executor.yaml",
	)

	output, err = shimExecutorCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to apply shim executor configuration: %w\nOutput: %s", err, string(output))
	}

	if err := config.SaveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("Spin Operator has been successfully deployed to the cluster!")
	return nil
}

// CreateServiceAccount creates a Kubernetes service account with workload identity configuration
func (s *Service) CreateServiceAccount(ctx context.Context, identityName string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ClusterName == "" || cfg.ResourceGroup == "" {
		return fmt.Errorf("no cluster is currently selected, use 'spin azure cluster use' first")
	}

	fmt.Println("Setting up kubectl with cluster credentials...")
	getCredsCmd := exec.Command(
		"az", "aks", "get-credentials",
		"--name", cfg.ClusterName,
		"--resource-group", cfg.ResourceGroup,
		"--subscription", s.subscriptionID,
		"--overwrite-existing",
	)

	fmt.Println("Executing command:", strings.Join(getCredsCmd.Args, " "))

	output, err := getCredsCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get Kubernetes credentials: %w\nOutput: %s", err, string(output))
	}

	identityClientID, err := s.getIdentityClientID(identityName, cfg.ResourceGroup)
	if err != nil {
		return fmt.Errorf("failed to get identity client ID: %w", err)
	}

	namespace := "default"

	fmt.Printf("Checking if service account '%s' exists...\n", identityName)
	checkCmd := exec.Command("kubectl", "get", "serviceaccount", identityName, "-n", namespace, "--ignore-not-found")
	output, err = checkCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check if service account exists: %w\nOutput: %s", err, string(output))
	}

	if strings.Contains(string(output), identityName) {
		fmt.Printf("Service account '%s' already exists in namespace '%s'\n", identityName, namespace)
		return nil
	}

	saYAML := fmt.Sprintf(`
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
  annotations:
    azure.workload.identity/client-id: %s
`, identityName, namespace, identityClientID)

	tempFile, err := os.CreateTemp("", "sa-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write([]byte(saYAML)); err != nil {
		return fmt.Errorf("failed to write service account YAML: %w", err)
	}
	tempFile.Close()

	fmt.Printf("Creating service account '%s'...\n", identityName)
	cmd := exec.Command("kubectl", "apply", "-f", tempFile.Name())
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create service account: %w\nOutput: %s", err, string(output))
	}

	fmt.Printf("Created service account '%s' in namespace '%s'\n", identityName, namespace)
	return nil
}

func (s *Service) getIdentityClientID(name, resourceGroup string) (string, error) {
	if resourceGroup == "" {
		cfg, err := config.LoadConfig()
		if err != nil {
			return "", fmt.Errorf("failed to load config: %w", err)
		}
		resourceGroup = cfg.ResourceGroup
	}

	cmd := exec.Command(
		"az", "identity", "show",
		"--name", name,
		"--resource-group", resourceGroup,
		"--subscription", s.subscriptionID,
		"--query", "clientId",
		"--output", "tsv",
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get identity client ID: %w\nOutput: %s", err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}

// CreateIdentity creates an Azure managed identity and sets up federated credentials
func (s *Service) CreateIdentity(ctx context.Context, identityName string, resourceGroup string, createServiceAccount bool) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if createServiceAccount && (cfg.ClusterName == "" || cfg.ResourceGroup == "") {
		return fmt.Errorf("no cluster is currently selected, use 'spin azure cluster use' first or set createServiceAccount to false")
	}

	fmt.Printf("Creating managed identity '%s'...\n", identityName)
	cmd := exec.Command(
		"az", "identity", "create",
		"--name", identityName,
		"--resource-group", resourceGroup,
		"--subscription", s.subscriptionID,
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create managed identity: %w\nOutput: %s", err, string(output))
	}

	clientID, err := s.getIdentityClientID(identityName, resourceGroup)
	if err != nil {
		return fmt.Errorf("failed to get identity client ID: %w", err)
	}

	if createServiceAccount {
		fmt.Printf("Creating Kubernetes service account for identity '%s'...\n", identityName)
		if err := s.CreateServiceAccount(ctx, identityName); err != nil {
			return fmt.Errorf("failed to create service account: %w", err)
		}

		fmt.Printf("Creating federated credential for identity '%s'...\n", identityName)
		if err := s.createFederatedCredential(identityName, clientID, cfg.ClusterName, resourceGroup); err != nil {
			return fmt.Errorf("failed to create federated identity credential: %w", err)
		}
	}

	cfg.IdentityName = identityName
	if err := config.SaveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save identity name to config: %w", err)
	}

	fmt.Printf("Created managed identity '%s' with client ID '%s'\n", identityName, clientID)
	return nil
}

// UseIdentity sets the current identity in the configuration
func (s *Service) UseIdentity(ctx context.Context, identityName string, resourceGroup string, createServiceAccount bool) error {
	clientID, err := s.getIdentityClientID(identityName, resourceGroup)
	if err != nil {
		return fmt.Errorf("failed to find managed identity '%s': %w", identityName, err)
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ClusterName == "" || cfg.ResourceGroup == "" {
		return fmt.Errorf("no cluster is currently selected, use 'spin azure cluster use' first")
	}

	if createServiceAccount {

		fmt.Printf("Creating Kubernetes service account for identity '%s'...\n", identityName)
		if err := s.CreateServiceAccount(ctx, identityName); err != nil {
			return fmt.Errorf("failed to create service account: %w", err)
		}

		fmt.Printf("Creating federated credential for identity '%s'...\n", identityName)
		if err := s.createFederatedCredential(identityName, clientID, cfg.ClusterName, resourceGroup); err != nil {
			return fmt.Errorf("failed to create federated credential: %w", err)
		}
	}

	cfg.IdentityName = identityName

	if err := config.SaveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Now using identity '%s' with client ID '%s'\n", identityName, clientID)
	return nil
}

// Create a federated identity credential for the managed identity
func (s *Service) createFederatedCredential(identityName, clientID, clusterName, resourceGroup string) error {
	oidcURL, err := s.getClusterOIDCIssuerURL(clusterName, resourceGroup)
	if err != nil {
		return fmt.Errorf("failed to get cluster OIDC issuer URL: %w", err)
	}

	namespace := "default"
	subject := fmt.Sprintf("system:serviceaccount:%s:%s", namespace, identityName)

	credName := fmt.Sprintf("%s-federated-credential", identityName)
	fmt.Printf("Creating federated identity credential '%s'...\n", credName)

	cmd := exec.Command(
		"az", "identity", "federated-credential", "create",
		"--name", credName,
		"--identity-name", identityName,
		"--resource-group", resourceGroup,
		"--subscription", s.subscriptionID,
		"--issuer", oidcURL,
		"--subject", subject,
		"--audiences", "api://AzureADTokenExchange",
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create federated identity credential: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// Get OIDC issuer URL for the cluster
func (s *Service) getClusterOIDCIssuerURL(clusterName, resourceGroup string) (string, error) {
	cmd := exec.Command(
		"az", "aks", "show",
		"--name", clusterName,
		"--resource-group", resourceGroup,
		"--subscription", s.subscriptionID,
		"--query", "oidcIssuerProfile.issuerUrl",
		"--output", "tsv",
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get cluster OIDC issuer URL: %w\nOutput: %s", err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}
