// // Copyright Project Harbor Authors
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// // http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
// package config

// import (
// 	"encoding/json"
// 	"fmt"
// 	"os"
// 	"path/filepath"
// 	"slices"

// 	"github.com/goharbor/go-client/pkg/sdk/v2.0/models"
// 	"github.com/goharbor/harbor-cli/pkg/api"
// 	"github.com/goharbor/harbor-cli/pkg/views/robot/create"
// 	"gopkg.in/yaml.v2"
// )

// type RobotPermissionConfig struct {
// 	Name        string           `yaml:"name" json:"name"`
// 	Description string           `yaml:"description" json:"description"`
// 	Duration    int64            `yaml:"duration" json:"duration"`
// 	Project     string           `yaml:"project" json:"project"`
// 	Permissions []PermissionSpec `yaml:"permissions" json:"permissions"`
// }

// type PermissionSpec struct {
// 	Resource  string   `yaml:"resource,omitempty" json:"resource,omitempty"`
// 	Resources []string `yaml:"resources,omitempty" json:"resources,omitempty"`
// 	Actions   []string `yaml:"actions" json:"actions"`
// }

// type RobotSecret struct {
// 	Name         string `json:"name"`
// 	ExpiresAt    int64  `json:"expires_at"`
// 	CreationTime string `json:"creation_time"`
// 	Secret       string `json:"secret"`
// }

// func LoadRobotConfigFromYAMLorJSON(filename string, fileType string, kind string) (*create.CreateView, error) {
// 	data, err := os.ReadFile(filename)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read YAML file: %v", err)
// 	}
// 	var config RobotPermissionConfig
// 	if fileType == "yaml" {
// 		if err := yaml.Unmarshal(data, &config); err != nil {
// 			return nil, fmt.Errorf("failed to parse YAML: %v", err)
// 		}
// 	} else if fileType == "json" {
// 		if err := json.Unmarshal(data, &config); err != nil {
// 			return nil, fmt.Errorf("failed to parse JSON: %v", err)
// 		}
// 	} else {
// 		return nil, fmt.Errorf("unsupported file type: %s, expected 'yaml' or 'json'", fileType)
// 	}

// 	opts := &create.CreateView{
// 		Name:        config.Name,
// 		Description: config.Description,
// 		Duration:    config.Duration,
// 		ProjectName: config.Project,
// 	}

// 	permissions, err := ProcessPermissions(config.Permissions, kind)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var accesses []*models.Access
// 	for _, perm := range permissions {
// 		access := &models.Access{
// 			Action:   perm.Action,
// 			Resource: perm.Resource,
// 		}
// 		accesses = append(accesses, access)
// 	}

// 	perm := &create.RobotPermission{
// 		Namespace: config.Project,
// 		Access:    accesses,
// 	}
// 	opts.Permissions = []*create.RobotPermission{perm}

// 	return opts, nil
// }

// func ProcessPermissions(specs []PermissionSpec, kind string) ([]models.Permission, error) {
// 	var result []models.Permission

// 	availablePerms, err := GetAllAvailablePermissions(kind)
// 	if err != nil {
// 		return nil, err
// 	}

// 	for _, spec := range specs {
// 		var resources []string

// 		if spec.Resource != "" {
// 			resources = []string{spec.Resource}
// 		} else if len(spec.Resources) > 0 {
// 			resources = spec.Resources
// 		} else {
// 			return nil, fmt.Errorf("permission must specify either 'resource' or 'resources'")
// 		}

// 		if containsWildcard(resources) {
// 			resources = getAllResourceNames(availablePerms)
// 		}

// 		for _, resource := range resources {
// 			if !isValidResource(resource, availablePerms) && resource != "*" {
// 				fmt.Printf("Warning: Resource '%s' is not valid and will be skipped\n", resource)
// 				continue
// 			}

// 			if containsWildcard(spec.Actions) {
// 				validActions := getValidActionsForResource(resource, availablePerms)
// 				for _, action := range validActions {
// 					result = append(result, models.Permission{
// 						Resource: resource,
// 						Action:   action,
// 					})
// 				}
// 			} else {
// 				for _, action := range spec.Actions {
// 					if isValidAction(resource, action, availablePerms) {
// 						result = append(result, models.Permission{
// 							Resource: resource,
// 							Action:   action,
// 						})
// 					} else {
// 						fmt.Printf("Warning: Action '%s' is not valid for resource '%s' and will be skipped\n",
// 							action, resource)
// 					}
// 				}
// 			}
// 		}
// 	}

// 	return result, nil
// }

// func LoadRobotConfigFromFile(filename string, kind string) (*create.CreateView, error) {
// 	var opts *create.CreateView
// 	var err error
// 	opts, err = LoadRobotConfigFromYAMLorJSON(filename, filepath.Ext(filename)[1:], kind)

// 	if err != nil {
// 		return nil, fmt.Errorf("failed to load configuration: %v", err)
// 	}
// 	if opts.Name == "" {
// 		return nil, fmt.Errorf("robot name cannot be empty")
// 	}
// 	if opts.Duration == 0 {
// 		return nil, fmt.Errorf("duration cannot be 0")
// 	}
// 	if opts.ProjectName == "" {
// 		return nil, fmt.Errorf("project name cannot be empty")
// 	}
// 	if len(opts.Permissions) == 0 || len(opts.Permissions[0].Access) == 0 {
// 		return nil, fmt.Errorf("no permissions specified")
// 	}

// 	projectExists := false
// 	projectsResp, err := api.ListAllProjects()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to list projects: %v", err)
// 	}

// 	for _, proj := range projectsResp.Payload {
// 		if proj.Name == opts.ProjectName {
// 			projectExists = true
// 			break
// 		}
// 	}

// 	if !projectExists {
// 		return nil, fmt.Errorf("project '%s' does not exist in Harbor", opts.ProjectName)
// 	}
// 	return opts, nil
// }

// func GetAllAvailablePermissions(kind string) (map[string][]string, error) {
// 	permsResp, err := api.GetPermissions()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get permissions: %v", err)
// 	}

// 	result := make(map[string][]string)
// 	var permissions []*models.Permission
// 	if kind == "system" {
// 		permissions = permsResp.Payload.System
// 	} else if kind == "project" {
// 		permissions = permsResp.Payload.Project
// 	} else {
// 		return nil, fmt.Errorf("invalid kind specified: %s, expected 'system' or 'project'", kind)
// 	}
// 	for _, perm := range permissions {
// 		resource := perm.Resource
// 		if _, exists := result[resource]; !exists {
// 			result[resource] = []string{}
// 		}
// 		result[resource] = append(result[resource], perm.Action)
// 	}

// 	return result, nil
// }

// func containsWildcard(items []string) bool {
// 	return slices.Contains(items, "*")
// }

// func getAllResourceNames(permissions map[string][]string) []string {
// 	resources := make([]string, 0, len(permissions))
// 	for resource := range permissions {
// 		resources = append(resources, resource)
// 	}
// 	return resources
// }

// func isValidResource(resource string, permissions map[string][]string) bool {
// 	_, exists := permissions[resource]
// 	return exists
// }

// func isValidAction(resource, action string, permissions map[string][]string) bool {
// 	actions, exists := permissions[resource]
// 	if !exists {
// 		return false
// 	}

// 	return slices.Contains(actions, action)
// }

//	func getValidActionsForResource(resource string, permissions map[string][]string) []string {
//		if actions, exists := permissions[resource]; exists {
//			return actions
//		}
//		return []string{}
//	}
//
// # Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/goharbor/go-client/pkg/sdk/v2.0/models"
	"github.com/goharbor/harbor-cli/pkg/api"
	"github.com/goharbor/harbor-cli/pkg/views/robot/create"
	"gopkg.in/yaml.v2"
)

type RobotPermissionConfig struct {
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Duration    int64            `yaml:"duration" json:"duration"`
	Project     string           `yaml:"project" json:"project"`
	Permissions []PermissionSpec `yaml:"permissions" json:"permissions"`
	// New fields for system robots
	Level    string         `yaml:"level,omitempty" json:"level,omitempty"`
	Projects []ProjectPerms `yaml:"projects,omitempty" json:"projects,omitempty"`
}

type ProjectPerms struct {
	Name        string           `yaml:"name" json:"name"`
	Permissions []PermissionSpec `yaml:"permissions" json:"permissions"`
}

type PermissionSpec struct {
	Resource  string   `yaml:"resource,omitempty" json:"resource,omitempty"`
	Resources []string `yaml:"resources,omitempty" json:"resources,omitempty"`
	Actions   []string `yaml:"actions" json:"actions"`
}

type RobotSecret struct {
	Name         string `json:"name"`
	ExpiresAt    int64  `json:"expires_at"`
	CreationTime string `json:"creation_time"`
	Secret       string `json:"secret"`
}

func LoadRobotConfigFromYAMLorJSON(filename string, fileType string, kind string) (*create.CreateView, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	var config RobotPermissionConfig
	if fileType == "yaml" {
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %v", err)
		}
	} else if fileType == "json" {
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported file type: %s, expected 'yaml' or 'json'", fileType)
	}

	opts := &create.CreateView{
		Name:        config.Name,
		Description: config.Description,
		Duration:    config.Duration,
		ProjectName: config.Project,
	}

	var robotPermissions []*create.RobotPermission

	// Handle system robot
	if kind == "system" {
		// Process system-level permissions
		systemPerms, err := ProcessPermissions(config.Permissions, "system")
		if err != nil {
			return nil, err
		}

		var systemAccesses []*models.Access
		for _, perm := range systemPerms {
			access := &models.Access{
				Action:   perm.Action,
				Resource: perm.Resource,
			}
			systemAccesses = append(systemAccesses, access)
		}

		robotPermissions = append(robotPermissions, &create.RobotPermission{
			Namespace: "/",
			Access:    systemAccesses,
			Kind:      "system",
		})

		// Process project-specific permissions if provided
		if len(config.Projects) > 0 {
			for _, proj := range config.Projects {
				projectPerms, err := ProcessPermissions(proj.Permissions, "project")
				if err != nil {
					return nil, err
				}

				var projectAccesses []*models.Access
				for _, perm := range projectPerms {
					access := &models.Access{
						Action:   perm.Action,
						Resource: perm.Resource,
					}
					projectAccesses = append(projectAccesses, access)
				}

				robotPermissions = append(robotPermissions, &create.RobotPermission{
					Namespace: proj.Name,
					Access:    projectAccesses,
					Kind:      "project",
				})
			}
		}
	} else {
		// Process project-level robot (backward compatibility)
		projectPerms, err := ProcessPermissions(config.Permissions, "project")
		if err != nil {
			return nil, err
		}

		var projectAccesses []*models.Access
		for _, perm := range projectPerms {
			access := &models.Access{
				Action:   perm.Action,
				Resource: perm.Resource,
			}
			projectAccesses = append(projectAccesses, access)
		}

		robotPermissions = append(robotPermissions, &create.RobotPermission{
			Namespace: config.Project,
			Access:    projectAccesses,
			Kind:      "project",
		})
	}

	opts.Permissions = robotPermissions
	return opts, nil
}

func ProcessPermissions(specs []PermissionSpec, kind string) ([]models.Permission, error) {
	var result []models.Permission

	availablePerms, err := GetAllAvailablePermissions(kind)
	if err != nil {
		return nil, err
	}

	for _, spec := range specs {
		var resources []string

		if spec.Resource != "" {
			resources = []string{spec.Resource}
		} else if len(spec.Resources) > 0 {
			resources = spec.Resources
		} else {
			return nil, fmt.Errorf("permission must specify either 'resource' or 'resources'")
		}

		if containsWildcard(resources) {
			resources = getAllResourceNames(availablePerms)
		}

		for _, resource := range resources {
			if !isValidResource(resource, availablePerms) && resource != "*" {
				fmt.Printf("Warning: Resource '%s' is not valid and will be skipped\n", resource)
				continue
			}

			if containsWildcard(spec.Actions) {
				validActions := getValidActionsForResource(resource, availablePerms)
				for _, action := range validActions {
					result = append(result, models.Permission{
						Resource: resource,
						Action:   action,
					})
				}
			} else {
				for _, action := range spec.Actions {
					if isValidAction(resource, action, availablePerms) {
						result = append(result, models.Permission{
							Resource: resource,
							Action:   action,
						})
					} else {
						fmt.Printf("Warning: Action '%s' is not valid for resource '%s' and will be skipped\n",
							action, resource)
					}
				}
			}
		}
	}

	return result, nil
}

func LoadRobotConfigFromFile(filename string, kind string) (*create.CreateView, error) {
	var opts *create.CreateView
	var err error

	ext := filepath.Ext(filename)
	if ext == "" {
		return nil, fmt.Errorf("file must have an extension")
	}

	fileType := ext[1:] // Remove the leading dot
	opts, err = LoadRobotConfigFromYAMLorJSON(filename, fileType, kind)

	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	// Basic validations
	if opts.Name == "" {
		return nil, fmt.Errorf("robot name cannot be empty")
	}
	if opts.Duration == 0 {
		return nil, fmt.Errorf("duration cannot be 0")
	}
	if len(opts.Permissions) == 0 {
		return nil, fmt.Errorf("no permissions specified")
	}

	// Special handling for system robots
	if kind == "system" && opts.ProjectName == "/" {
		// For system robots, we need to validate any project-specific permissions
		projectsResp, err := api.ListAllProjects()
		if err != nil {
			return nil, fmt.Errorf("failed to list projects: %v", err)
		}

		// Create a map of valid project names for quick lookup
		validProjects := make(map[string]bool)
		for _, proj := range projectsResp.Payload {
			validProjects[proj.Name] = true
		}

		// Validate each project-specific permission
		for _, perm := range opts.Permissions {
			if perm.Kind == "project" && perm.Namespace != "/" {
				if !validProjects[perm.Namespace] {
					return nil, fmt.Errorf("project '%s' specified in permissions does not exist in Harbor", perm.Namespace)
				}
			}
		}
	} else {
		// For project robots or system robots with a specific project
		if opts.ProjectName == "" {
			return nil, fmt.Errorf("project name cannot be empty")
		}

		// Skip validation for "/" which is special for system robots
		if opts.ProjectName != "/" {
			// Validate that project exists
			projectExists := false
			projectsResp, err := api.ListAllProjects()
			if err != nil {
				return nil, fmt.Errorf("failed to list projects: %v", err)
			}

			for _, proj := range projectsResp.Payload {
				if proj.Name == opts.ProjectName {
					projectExists = true
					break
				}
			}

			if !projectExists {
				return nil, fmt.Errorf("project '%s' does not exist in Harbor", opts.ProjectName)
			}
		}
	}

	return opts, nil
}

func GetAllAvailablePermissions(kind string) (map[string][]string, error) {
	permsResp, err := api.GetPermissions()
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %v", err)
	}

	result := make(map[string][]string)
	var permissions []*models.Permission
	if kind == "system" {
		permissions = permsResp.Payload.System
	} else if kind == "project" {
		permissions = permsResp.Payload.Project
	} else {
		return nil, fmt.Errorf("invalid kind specified: %s, expected 'system' or 'project'", kind)
	}
	for _, perm := range permissions {
		resource := perm.Resource
		if _, exists := result[resource]; !exists {
			result[resource] = []string{}
		}
		result[resource] = append(result[resource], perm.Action)
	}

	return result, nil
}

func containsWildcard(items []string) bool {
	return slices.Contains(items, "*")
}

func getAllResourceNames(permissions map[string][]string) []string {
	resources := make([]string, 0, len(permissions))
	for resource := range permissions {
		resources = append(resources, resource)
	}
	return resources
}

func isValidResource(resource string, permissions map[string][]string) bool {
	_, exists := permissions[resource]
	return exists
}

func isValidAction(resource, action string, permissions map[string][]string) bool {
	actions, exists := permissions[resource]
	if !exists {
		return false
	}

	return slices.Contains(actions, action)
}

func getValidActionsForResource(resource string, permissions map[string][]string) []string {
	if actions, exists := permissions[resource]; exists {
		return actions
	}
	return []string{}
}
