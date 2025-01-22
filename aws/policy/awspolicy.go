package policy

import (
	"encoding/json"

	"github.com/pkg/errors"
)

type Policy struct {
	Version    string      `json:"Version"`
	Id         string      `json:"ID,omitempty"`
	Statements []Statement `json:"Statement"`
}

type Statement struct {
	StatementId string              `json:"StatementID,omitempty"`
	Effect      string              `json:"Effect"`
	Principal   map[string][]string `json:"Principal,omitempty"`

	Action        []string `json:"Action"`
	Resource      []string `json:"Resource,omitempty"`
	HasConditions bool     // This is the only thing we need to know at this moment

	NotPrincipal map[string][]string `json:"NotPrincipal,omitempty"`
	NotResource  []string            `json:"NotResource,omitempty"`
	NotAction    []string            `json:"NotAction,omitempty"`

	Condition []string `json:"Condition,omitempty"`
}

func (policyJSON *Policy) UnmarshalJSON(policy []byte) error {
	var raw interface{}

	err := json.Unmarshal(policy, &raw)
	if err != nil {
		return errors.Errorf("unmashalling policy: %s", err.Error())
	}

	if topObject, ok := raw.(map[string]interface{}); ok {
		for key, value := range topObject {
			switch key {
			case "Version":
				policyJSON.Version = value.(string)
			case "ID":
				policyJSON.Id = value.(string)
			case "Statement":
				policyJSON.Statements = parseStatements(value)
			}
		}
	}

	return nil
}

func parseStatements(obj interface{}) []Statement {
	statements := make([]Statement, 0)

	switch statementsObj := obj.(type) {
	case map[string]interface{}: // Single statement
		statementMap := Statement{}
		// Parse statement
		statementMap.Parse(statementsObj)
		statements = append(statements, statementMap)

	case []interface{}: // Multiple statements
		for _, stmObj := range statementsObj {
			stm := Statement{}
			statementMap := stmObj.(map[string]interface{})
			stm.Parse(statementMap)
			statements = append(statements, stm)
		}
	}

	return statements
}

// Parse parses a single statement from an AWS IAM Policy
func (s *Statement) Parse(stm map[string]interface{}) {
	for key, val := range stm {
		switch key {
		case "StatementID":
			s.StatementId = val.(string)
		case "Effect":
			s.Effect = val.(string)
		case "Principal":
			s.Principal = parsePrincipal(val.(map[string]interface{}))
		case "NotPrincipal":
			s.NotPrincipal = parsePrincipal(val.(map[string]interface{}))
		case "Action":
			s.Action = parseStringOrStringArray(val)
		case "NotAction":
			s.NotAction = parseStringOrStringArray(val)
		case "Resource":
			s.Resource = parseStringOrStringArray(val)
		case "NotResource":
			s.NotResource = parseStringOrStringArray(val)
		case "Condition":
			s.HasConditions = true
		}
	}
}

func parseStringOrStringArray(val interface{}) []string {
	switch v := val.(type) {
	case string:
		return []string{v}
	case []interface{}:
		strs := make([]string, 0, len(v))
		for _, s := range v {
			strs = append(strs, s.(string))
		}

		return strs
	}

	return nil
}

func parsePrincipal(principalMap map[string]interface{}) map[string][]string {
	principal := make(map[string][]string)

	for pKey, pVal := range principalMap {
		switch principalVal := pVal.(type) {
		case string:
			principal[pKey] = []string{principalVal}
		case []interface{}:
			principals := make([]string, 0, len(principalVal))

			for _, p := range principalVal {
				principals = append(principals, p.(string))
			}

			principal[pKey] = principals
		}
	}

	return principal
}
