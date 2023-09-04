var expect = require('chai').expect;
var monitorEndpointProtection = require('./monitorEndpointProtection');

const policyAssignments = [
    {
        "sku": {
        "name": "A0",
        "tier": "Free"
        },
        "id": "/subscriptions/1234/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
        "type": "Microsoft.Authorization/policyAssignments",
        "name": "SecurityCenterBuiltIn",
        "location": "eastus",
        "displayName": "ASC Default (subscription: 1234)",
        "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8",
        "scope": "/subscriptions/1234",
        "notScopes": [],
        "parameters": {
            "vmssOsVulnerabilitiesMonitoringEffect": {
            "value": "AuditIfNotExists"
            },
            "systemConfigurationsMonitoringEffect": {
            "value": "AuditIfNotExists"
            },
            "endpointProtectionMonitoringEffect": {
            "value": "Audit"
            },
            "diskEncryptionMonitoringEffect": {
            "value": "Audit"
            },
            "networkSecurityGroupsMonitoringEffect": {
            "value": "Disabled"
            },
            "nextGenerationFirewallMonitoringEffect": {
            "value": "Disabled"
            },
            "vulnerabilityAssesmentMonitoringEffect": {
            "value": "Disabled"
            },
            "storageEncryptionMonitoringEffect": {
            "value": "AuditIfNotExists"
            },
            "jitNetworkAccessMonitoringEffect": {
            "value": "Disabled"
            },
            "adaptiveApplicationControlsMonitoringEffect": {
            "value": "AuditIfNotExists"
            },
            "adaptiveApplicationControlsUpdateMonitoringEffect": {
            "value": "Disabled"
            },
            "sqlAuditingMonitoringEffect": {
            "value": "Disabled"
            },
            "sqlEncryptionMonitoringEffect": {
            "value": "Disabled"
            },
            "sqlServerAuditingMonitoringEffect": {
            "value": "Disabled"
            },
            "secureTransferToStorageAccountMonitoringEffect": {
            "value": "Disabled"
            },
            "identityDesignateLessThanOwnersMonitoringEffect": {
            "value": "Disabled"
            },
            "identityRemoveExternalAccountWithWritePermissionsMonitoringEffect": {
            "value": "Disabled"
            },
            "disableIPForwardingMonitoringEffect": {
            "value": "Disabled"
            }
        },
        "description": "This is the default set of policies monitored by Azure Security Center. It was automatically assigned as part of onboarding to Security Center. The default assignment contains only audit policies. For more information please visit https://aka.ms/ascpolicies",
        "metadata": {
            "assignedBy": "cariel@cloudsploit.com ",
            "parameterScopes": {},
            "createdBy": "709d03b9-72f9-4c49-ba6e-935fd066886f",
            "createdOn": "2019-02-22T01:37:48.8576719Z",
            "updatedBy": "ef21d0c2-9e1a-422c-b324-c39f584fd4b9",
            "updatedOn": "2021-06-30T01:58:11.9141222Z"
        },
        "enforcementMode": "Default"     
    },
    {
        "sku": {
          "name": "A0",
          "tier": "Free"
        },
        "id": "/subscriptions/1234/providers/Microsoft.Authorization/policyAssignments/7a9dabe0d6244e9683d56a79",
        "type": "Microsoft.Authorization/policyAssignments",
        "name": "7a9dabe0d6244e9683d56a79",
        "location": "eastus",
        "displayName": "Monitor unencrypted SASASA",
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0961003e-5a0a-4549-abde-af6a37f2724d",
        "scope": "/subscriptions/1234",
        "notScopes": [],
        "parameters": {
          "effect": {
            "value": "Disabled"
          }
        },
        "metadata": {
          "assignedBy": "cariel@cloudsploit.com ",
          "parameterScopes": {},
          "createdBy": "d0222e76-19f3-46f1-8705-af53043c1ff8",
          "createdOn": "2019-04-18T00:34:32.2202483Z",
          "updatedBy": null,
          "updatedOn": null
        },
        "enforcementMode": "Default"
    },
    {
        "sku": {
        "name": "A0",
        "tier": "Free"
        },
        "id": "/subscriptions/1234/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
        "type": "Microsoft.Authorization/policyAssignments",
        "name": "SecurityCenterBuiltIn",
        "location": "eastus",
        "displayName": "ASC Default (subscription: 1234)",
        "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8",
        "scope": "/subscriptions/1234",
        "notScopes": [],
        "parameters": {
            "vmssOsVulnerabilitiesMonitoringEffect": {
            "value": "AuditIfNotExists"
            },
            "systemConfigurationsMonitoringEffect": {
            "value": "AuditIfNotExists"
            },
            "endpointProtectionMonitoringEffect": {
            "value": "Disabled"
            },
            "diskEncryptionMonitoringEffect": {
            "value": "Disabled"
            },
            "networkSecurityGroupsMonitoringEffect": {
            "value": "Disabled"
            },
            "nextGenerationFirewallMonitoringEffect": {
            "value": "Disabled"
            },
            "vulnerabilityAssesmentMonitoringEffect": {
            "value": "Disabled"
            },
            "storageEncryptionMonitoringEffect": {
            "value": "Disabled"
            },
            "jitNetworkAccessMonitoringEffect": {
            "value": "Disabled"
            },
            "adaptiveApplicationControlsMonitoringEffect": {
            "value": "Disabled"
            },
            "adaptiveApplicationControlsUpdateMonitoringEffect":  {
            "value": ''
            },
            "sqlAuditingMonitoringEffect": {
            "value": "Disabled"
            },
            "sqlEncryptionMonitoringEffect": {
            "value": "Disabled"
            },
            "sqlServerAuditingMonitoringEffect": {
            "value": "Disabled"
            },
            "secureTransferToStorageAccountMonitoringEffect": {
            "value": "Disabled"
            },
            "identityDesignateLessThanOwnersMonitoringEffect": {
            "value": "Disabled"
            },
            "identityRemoveExternalAccountWithWritePermissionsMonitoringEffect": {
            "value": "Disabled"
            },
            "disableIPForwardingMonitoringEffect": {
            "value": "Disabled"
            }
        },
        "description": "This is the default set of policies monitored by Azure Security Center. It was automatically assigned as part of onboarding to Security Center. The default assignment contains only audit policies. For more information please visit https://aka.ms/ascpolicies",
        "metadata": {
            "assignedBy": "cariel@cloudsploit.com ",
            "parameterScopes": {},
            "createdBy": "709d03b9-72f9-4c49-ba6e-935fd066886f",
            "createdOn": "2019-02-22T01:37:48.8576719Z",
            "updatedBy": "ef21d0c2-9e1a-422c-b324-c39f584fd4b9",
            "updatedOn": "2021-06-30T01:58:11.9141222Z"
        },
        "enforcementMode": "Default"     
    },
];

const createCache = (policyAssignment) => {
    let settings = {};
    if (policyAssignment) {
        settings['data'] = policyAssignment;
    }
    return {
        policyAssignments: {
            list: {
                'eastus': settings
            }
        }
    };
};

describe('monitorEndpointProtection', function() {
    describe('run', function() {
        it('should give failing result if No existing Policy Assignments found', function(done) {
            const cache = createCache([]);
            monitorEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Policy Assignments found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if There are no ASC Default Policy Assignments', function(done) {
            const cache = createCache([policyAssignments[1]]);
            monitorEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('There are no ASC Default Policy Assignments');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Policy Assignments', function(done) {
            const cache = createCache();
            monitorEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Policy Assignments');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Monitor Endpoint Protection enabled', function(done) {
            const cache = createCache([policyAssignments[0]]);
            monitorEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Monitor Endpoint Protection disabled', function(done) {
            const cache = createCache([policyAssignments[2]]);
            monitorEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});