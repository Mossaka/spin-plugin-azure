package bind

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

type CosmosDBService struct {
	credential     azcore.TokenCredential
	subscriptionID string
}

func NewCosmosDBService(credential azcore.TokenCredential, subscriptionID string) *CosmosDBService {
	return &CosmosDBService{
		credential:     credential,
		subscriptionID: subscriptionID,
	}
}

func (s *CosmosDBService) BindCosmosDB(ctx context.Context, name, resourceGroup, identityName, identityResourceGroup string) error {
	if err := s.validateCosmosDBAccount(name, resourceGroup); err != nil {
		return err
	}

	identityPrincipalID, err := s.getIdentityPrincipalID(identityName, identityResourceGroup)
	if err != nil {
		return err
	}

	if err := s.assignRoleToCosmosDB(identityPrincipalID, name, resourceGroup); err != nil {
		return err
	}

	fmt.Printf("Successfully bound CosmosDB '%s' to identity '%s'\n", name, identityName)

	return nil
}

// BindCosmosDBToUser assigns the CosmosDB Data Contributor role to a user identified by their principalID
func (s *CosmosDBService) BindCosmosDBToUser(ctx context.Context, name, resourceGroup, userPrincipalID string) error {
	if err := s.validateCosmosDBAccount(name, resourceGroup); err != nil {
		return err
	}

	if err := s.assignRoleToCosmosDB(userPrincipalID, name, resourceGroup); err != nil {
		return err
	}

	fmt.Printf("Successfully bound CosmosDB '%s' to user with ID '%s'\n", name, userPrincipalID)

	return nil
}

func (s *CosmosDBService) validateCosmosDBAccount(name, resourceGroup string) error {
	cmd := exec.Command(
		"az", "cosmosdb", "check-name-exists",
		"--name", name,
		"--subscription", s.subscriptionID,
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check if CosmosDB exists: %w\nOutput: %s", err, string(output))
	}

	cmd = exec.Command(
		"az", "cosmosdb", "show",
		"--name", name,
		"--resource-group", resourceGroup,
		"--subscription", s.subscriptionID,
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CosmosDB '%s' not found in resource group '%s': %w\nOutput: %s",
			name, resourceGroup, err, string(output))
	}

	return nil
}

func (s *CosmosDBService) getIdentityPrincipalID(name, resourceGroup string) (string, error) {
	cmd := exec.Command(
		"az", "identity", "show",
		"--name", name,
		"--resource-group", resourceGroup,
		"--subscription", s.subscriptionID,
		"--query", "principalId",
		"--output", "tsv",
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get identity principal ID: %w\nOutput: %s", err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}

func (s *CosmosDBService) assignRoleToCosmosDB(identityPrincipalID, cosmosDBName, resourceGroup string) error {
	cosmosDBResourceID, err := s.getCosmosDBResourceID(cosmosDBName, resourceGroup)
	if err != nil {
		return err
	}

	roleDefinitionID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DocumentDB/databaseAccounts/%s/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002", s.subscriptionID, resourceGroup, cosmosDBName)

	cmd := exec.Command(
		"az", "cosmosdb", "sql", "role", "assignment", "create",
		"--account-name", cosmosDBName,
		"--resource-group", resourceGroup,
		"--role-definition-id", roleDefinitionID,
		"--principal-id", identityPrincipalID,
		"--scope", cosmosDBResourceID,
		"--subscription", s.subscriptionID,
	)

	fmt.Println("Executing command:", strings.Join(cmd.Args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to assign role to CosmosDB: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func (s *CosmosDBService) getCosmosDBResourceID(name, resourceGroup string) (string, error) {
	cmd := exec.Command(
		"az", "cosmosdb", "show",
		"--name", name,
		"--resource-group", resourceGroup,
		"--subscription", s.subscriptionID,
		"--query", "id",
		"--output", "tsv",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get CosmosDB resource ID: %w\nOutput: %s", err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}
