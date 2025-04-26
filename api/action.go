package api

import "context"

type ActionFunc func(ctx context.Context, environment map[string]any, defaultClaims map[string]any) (map[string]any, error)

type Action struct {
	Name            string
	GrantType       string
	ServiceName     string
	ApplicationName string
	ActionFunc      ActionFunc
	Environment     map[string]any
}

// shouldExecuteAction returns true if the action should be executed.
func (a *Action) shouldExecuteAction(grantType string, serviceName string, appName string) bool {
	// immediately return true if the action should be executed in all cases
	if a.GrantType == "" && a.ServiceName == "" && a.ApplicationName == "" {
		return true
	}

	if a.GrantType != "" && a.GrantType != grantType {
		return false
	}

	if a.ServiceName != "" && a.ServiceName != serviceName {
		return false
	}

	if a.ApplicationName != "" && a.ApplicationName != appName {
		return false
	}

	return true
}

func (a *Action) Execute(ctx context.Context, grantType string, serviceName string, appName string, defaultClaims map[string]any) (map[string]any, error) {
	if !a.shouldExecuteAction(grantType, serviceName, appName) {
		return defaultClaims, nil
	}

	return a.ActionFunc(ctx, a.Environment, defaultClaims)
}
