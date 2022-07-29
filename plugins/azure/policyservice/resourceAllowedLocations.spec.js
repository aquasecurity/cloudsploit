var expect = require('chai').expect;
var resourceAllowedLocations = require('./resourceAllowedLocations');

const policyAssignments = [
    {
        "sku": {
          "name": "A0",
          "tier": "Free"
        },
        "id": "/subscriptions/1234/providers/Microsoft.Authorization/policyAssignments/db6d35583b2147ac96dcb3ca",
        "type": "Microsoft.Authorization/policyAssignments",
        "name": "db6d35583b2147ac96dcb3ca",
        "displayName": "Allowed locations",
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c",
        "scope": "/subscriptions/1234",
        "notScopes": [],
        "parameters": {
          "listOfAllowedLocations": {
            "value": [
              "asia",
              "asiapacific",
              "australia",
              "australiacentral",
              "australiacentral2",
              "australiaeast",
              "australiasoutheast",
              "brazil",
              "brazilsouth",
              "brazilsoutheast",
              "canada",
              "canadacentral",
              "canadaeast",
              "centralindia",
              "centralus",
              "centralusstage",
              "eastasia",
              "eastasiastage",
              "eastus",
              "eastusstage",
              "eastus2",
              "eastus2stage",
              "europe",
              "france",
              "francecentral",
              "francesouth",
              "germany",
              "germanynorth",
              "germanywestcentral",
              "global",
              "india",
              "japan",
              "japaneast",
              "japanwest",
              "jioindiacentral",
              "jioindiawest",
              "korea",
              "koreacentral",
              "koreasouth",
              "northcentralus",
              "northcentralusstage",
              "northeurope",
              "norway",
              "norwayeast",
              "norwaywest",
              "singapore",
              "southafrica",
              "southafricanorth",
              "southafricawest",
              "southcentralus",
              "southcentralusstage",
              "southindia",
              "southeastasia",
              "southeastasiastage",
              "swedencentral",
              "switzerland",
              "switzerlandnorth",
              "switzerlandwest",
              "uaecentral",
              "uaenorth",
              "uksouth",
              "ukwest",
              "uae",
              "uk",
              "unitedstates",
              "unitedstateseuap",
              "westcentralus",
              "westeurope",
              "westindia",
              "westus",
              "westusstage",
              "westus2",
              "westus2stage",
              "westus3"
            ]
          }
        },
        "metadata": {
          "assignedBy": "Akhtar pucit",
          "parameterScopes": {
            "listOfAllowedLocations": "/subscriptions/1234"
          },
          "createdBy": "f3eb1c86-38e5-40d0-b120-e7476956bc8e",
          "createdOn": "2022-07-15T16:26:12.6623135Z",
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
        "id": "/subscriptions/123/providers/Microsoft.Authorization/policyAssignments/9817efd5921b4d59ae85b5a1",
        "type": "Microsoft.Authorization/policyAssignments",
        "name": "9817efd5921b4d59ae85b5a1",
        "location": "eastus",
        "displayName": "Monitor unencrypted VM Disks in Azure Security Center",
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0961003e-5a0a-4549-abde-af6a37f2724d",
        "scope": "/subscriptions/123",
        "notScopes": [],
        "parameters": {},
        "metadata": {
          "assignedBy": "cariel@cloudsploit.com ",
          "parameterScopes": {},
          "createdBy": "d0222e76-19f3-46f1-8705-af53043c1ff8",
          "createdOn": "2019-05-22T15:55:48.8730114Z",
          "updatedBy": null,
          "updatedOn": null
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
                'global': settings
            }
        }
    };
};

// const createErrorCache = () => {
//     return {
//         policyAssignments: {
//             list: {
//                 'global': {}
//             }
//         }
//     };
// };

describe('resourceAllowedLocations', function() {
    describe('run', function() {
        it('should give failing result if No existing Policy Assignments found', function(done) {
            const cache = createCache([]);
            resourceAllowedLocations.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Policy Assignments found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query for Policy Assignments', function(done) {
            const cache = createCache();
            resourceAllowedLocations.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Policy Assignments');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if The policy to audit resources launched in allowed locations is enabled', function(done) {
            const cache = createCache([policyAssignments[0]]);
            resourceAllowedLocations.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The policy to audit resources launched in allowed locations is enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if No existing assignment for the resources launched in allowed locations policy', function(done) {
            const cache = createCache([policyAssignments[1]]);
            resourceAllowedLocations.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing assignment for the resources launched in allowed locations policy');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});