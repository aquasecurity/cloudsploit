var expect = require('chai').expect;
var resourceLocationMatch = require('./resourceLocationMatch');

const policyAssignments = [
    {
        "sku": {
          "name": "A0",
          "tier": "Free"
        },
        "id": "/subscriptions/12345/providers/Microsoft.Authorization/policyAssignments/69030cac631c4ede9355aa9b",
        "type": "Microsoft.Authorization/policyAssignments",
        "name": "69030cac631c4ede9355aa9b",
        "displayName": "Audit resource location matches resource group location",
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/0a914e76-4921-4c19-b460-a2d36003525a",
        "scope": "/subscriptions/12345",
        "notScopes": [
          "/subscriptions/12345/resourceGroups/sadeedrg"
        ],
        "parameters": {},
        "metadata": {
          "assignedBy": "Sadeed Rehman",
          "parameterScopes": {},
          "createdBy": "d198cb4d-de06-40ff-8fc4-4f643fbeabc5",
          "createdOn": "2022-07-18T13:44:25.7283635Z",
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

describe('resourceLocationMatch', function() {
    describe('run', function() {
        it('should give failing result if No existing Policy Assignments found', function(done) {
            const cache = createCache([]);
            resourceLocationMatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Policy Assignments found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query for Policy Assignments', function(done) {
            const cache = createCache();
            resourceLocationMatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Policy Assignments');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if The policy to audit matching resource location to resource group location is assigned', function(done) {
            const cache = createCache([policyAssignments[0]]);
            resourceLocationMatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The policy to audit matching resource location to resource group location is assigned');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if No existing assignment for the resource location matches resource group location policy', function(done) {
            const cache = createCache([policyAssignments[1]]);
            resourceLocationMatch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing assignment for the resource location matches resource group location policy');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});