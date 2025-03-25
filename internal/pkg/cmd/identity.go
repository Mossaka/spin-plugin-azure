package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spinframework/spin-plugin-azure/internal/pkg/aks"
	"github.com/spinframework/spin-plugin-azure/internal/pkg/config"
)

func NewIdentityCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage Azure managed identities for Spin workloads",
		Long:  `Create and manage Azure managed identities and Kubernetes service accounts for Spin workloads.`,
	}

	cmd.AddCommand(newIdentityCreateCommand())
	cmd.AddCommand(newIdentityUseCommand())

	return cmd
}

func newIdentityCreateCommand() *cobra.Command {
	var name, resourceGroup string
	var skipServiceAccount bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Azure managed identity with Kubernetes service account",
		Long:  `Create a new Azure managed identity and set up a Kubernetes service account with federated credentials.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				name = "workload-identity"
			}

			cfg, err := config.LoadConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if cfg.SubscriptionID == "" {
				return fmt.Errorf("subscription ID not set, please set it using `spin azure login`")
			}

			if resourceGroup == "" {
				resourceGroup = cfg.ResourceGroup
			}

			if resourceGroup == "" {
				return fmt.Errorf("resource group is required, please specify with --resource-group")
			}

			credential, err := config.GetAzureCredential()
			if err != nil {
				return fmt.Errorf("failed to get Azure credential: %w", err)
			}

			aksService, err := aks.NewService(credential, cfg.SubscriptionID)
			if err != nil {
				return fmt.Errorf("failed to create AKS service: %w", err)
			}

			ctx := context.Background()

			createServiceAccount := !skipServiceAccount
			if err := aksService.CreateIdentity(ctx, name, resourceGroup, createServiceAccount); err != nil {
				return fmt.Errorf("failed to create managed identity: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "workload-identity", "Name of the identity to create")
	cmd.Flags().StringVar(&resourceGroup, "resource-group", "", "Resource group for the identity (defaults to the resource group of the current cluster)")
	cmd.Flags().BoolVar(&skipServiceAccount, "skip-service-account", false, "Skip Kubernetes service account creation (default to false)")
	return cmd
}

func newIdentityUseCommand() *cobra.Command {
	var name, resourceGroup string
	var createServiceAccount bool

	cmd := &cobra.Command{
		Use:   "use",
		Short: "Set the current Azure managed identity",
		Long:  `Set the current Azure managed identity`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if cfg.SubscriptionID == "" {
				return fmt.Errorf("subscription ID not set, please set it using `spin azure login`")
			}

			if resourceGroup == "" {
				if cfg.ResourceGroup == "" {
					return fmt.Errorf("--resource-group is required or use 'spin azure cluster use' to select a cluster first")
				}

				resourceGroup = cfg.ResourceGroup
			}

			credential, err := config.GetAzureCredential()
			if err != nil {
				return fmt.Errorf("failed to get Azure credential: %w", err)
			}

			aksService, err := aks.NewService(credential, cfg.SubscriptionID)
			if err != nil {
				return fmt.Errorf("failed to create AKS service: %w", err)
			}

			ctx := context.Background()

			if err := aksService.UseIdentity(ctx, name, resourceGroup, createServiceAccount); err != nil {
				return fmt.Errorf("failed to use identity: %w", err)
			}

			fmt.Printf("Using identity '%s' for Spin workloads\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Name of the identity to use (required)")
	cmd.Flags().StringVar(&resourceGroup, "resource-group", "", "Resource group containing the identity (defaults to the resource group of the current cluster)")
	cmd.Flags().BoolVar(&createServiceAccount, "create-service-account", false, "Create a Kubernetes service account for this identity")
	if err := cmd.MarkFlagRequired("name"); err != nil {
		panic(fmt.Sprintf("failed to mark flag 'name' as required: %v", err))
	}
	return cmd
}
