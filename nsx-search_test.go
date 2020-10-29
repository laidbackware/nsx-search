package main

import (
	"testing"
)

func checkResource(apiType string, apiName string, t *testing.T, expected bool) {
	apiResources := getAPIResouces()
	_, found := Find(apiResources[apiType], apiName)
	if !found == expected {
		t.Errorf("%s not found in the %s api map", apiName, apiType)
	}
}

func TestCheckObjectIsValid(t *testing.T) {
	checkResource("manager", "LogicalRouter", t, true)
	checkResource("manager", "Tier0", t, false)
	checkResource("policy", "Tier0", t, true)
	checkResource("policy", "LogicalRouter", t, false)
}

func TestGenerateURL(t *testing.T) {
	// hostString := "test"
	// hostName = &hostString
	hostName = "test"
	fullURL := generateURL("LogicalRouter", "tier0", "/api/v1")
	expectedURL := "https://test/api/v1/search/query?query=resource_type:LogicalRouter+AND+display_name%3Atier0-gw"
	if fullURL != expectedURL {
		t.Errorf("Did not generate correct url")
	}
}
