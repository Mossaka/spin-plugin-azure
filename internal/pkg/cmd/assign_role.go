package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spinframework/spin-plugin-azure/internal/pkg/bind"
	"github.com/spinframework/spin-plugin-azure/internal/pkg/config"
)

func NewAssignRoleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assign-role",
		Short: "Assign Azure RBAC roles to managed identities",
		Long:  `Assign Azure RBAC roles to managed identities for accessing Azure services like CosmosDB.`,
	}

	cmd.AddCommand(newBindCosmosDBCommand())

	return cmd
}

func newBindCosmosDBCommand() *cobra.Command {
	var name, resourceGroup, identityName, identityResourceGroup, userID string

	cmd := &cobra.Command{
		Use:   "cosmosdb",
		Short: "Assign Azure roles for CosmosDB access",
		Long:  `Assign the necessary Azure RBAC roles to a managed identity or user for accessing an Azure CosmosDB instance.`,
		Example: `
  # Assign the CosmosDB Data Contributor role to a managed identity after 'spin azure identity create / use'
  # This will use the managed identity set in the current config and the same resource group as the CosmosDB account
  spin azure assign-role cosmosdb --name my-cosmos

  # Assign the CosmosDB Data Contributor role to a user
  spin azure assign-role cosmosdb --name my-cosmos --resource-group my-rg --user-id user@example.com

  # Assign the CosmosDB Data Contributor role to a managed identity
  spin azure assign-role cosmosdb --name my-cosmos --resource-group my-rg --identity my-identity --identity-resource-group my-identity-rg`,
		RunE: func(cmd *cobra.Command, args []string) error {
			credential, err := config.GetAzureCredential()
			if err != nil {
				return fmt.Errorf("failed to get Azure credential: %w", err)
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
				return fmt.Errorf("resource group for CosmosDB not set, please set it using --resource-group")
			}

			cosmosDBService := bind.NewCosmosDBService(credential, cfg.SubscriptionID)

			if userID != "" {
				userPrincipalID, err := getUserPrincipalID(userID)
				if err != nil {
					return fmt.Errorf("failed to get user ID: %w", err)
				}

				fmt.Printf("Assigning CosmosDB Data Contributor role to user '%s' for CosmosDB account '%s' (in resource group '%s')...\n",
					userID, name, resourceGroup)

				ctx := context.Background()
				if err := cosmosDBService.BindCosmosDBToUser(ctx, name, resourceGroup, userPrincipalID); err != nil {
					return fmt.Errorf("failed to assign role to CosmosDB: %w", err)
				}
			} else {
				if identityName == "" {
					identityName = cfg.IdentityName
				}

				if identityName == "" {
					return fmt.Errorf("identity name not set, please set it using --identity or --user-identity")
				}

				if identityResourceGroup == "" {
					identityResourceGroup = resourceGroup
				}

				fmt.Printf("Assigning CosmosDB Data Contributor role to identity '%s' (in resource group '%s') for CosmosDB account '%s' (in resource group '%s')...\n",
					identityName, identityResourceGroup, name, resourceGroup)

				ctx := context.Background()
				if err := cosmosDBService.BindCosmosDB(ctx, name, resourceGroup, identityName, identityResourceGroup); err != nil {
					return fmt.Errorf("failed to assign role to CosmosDB: %w", err)
				}
			}

			fmt.Printf("Successfully assigned roles to CosmosDB '%s'\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Name of the CosmosDB account (required)")
	cmd.Flags().StringVar(&resourceGroup, "resource-group", "", "Resource group of the CosmosDB account")
	cmd.Flags().StringVar(&identityName, "identity", "", "Name of the managed identity to assign roles to (mutually exclusive with --user-identity)")
	cmd.Flags().StringVar(&identityResourceGroup, "identity-resource-group", "", "Resource group of the managed identity (defaults to the CosmosDB resource group if not specified)")
	cmd.Flags().StringVar(&userID, "user-identity", "", "Email of the user to assign roles to (mutually exclusive with --identity)")

	if err := cmd.MarkFlagRequired("name"); err != nil {
		panic(fmt.Sprintf("failed to mark flag 'name' as required: %v", err))
	}

	cmd.MarkFlagsMutuallyExclusive("identity", "user-identity")
	return cmd
}

// getUserPrincipalID retrieves the Azure AD User ID (object ID) for a given email
func getUserPrincipalID(email string) (string, error) {
	cmd := exec.Command(
		"az", "ad", "user", "show",
		"--id", email,
		"--query", "id",
		"--output", "tsv",
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get user ID for '%s': %w\nOutput: %s", email, err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}
