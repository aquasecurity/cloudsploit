var expect = require('chai').expect;
var acrManagedIdentityEnabled = require('./acrManagedIdentityEnabled');

registries = [
    {
        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
        "name": "testregistry12543",
        "type": "Microsoft.ContainerRegistry/registries",
        "location": "eastus",
        "tags": {},
        "anonymousPullEnabled": true,
        "sku": {
            "name": "Premium",
            "tier": "Premium"
        },
        "policies": {
            "trustPolicy": {
              "type": "Notary",
              "status": "disabled"
            },
        },
        "identity": {
            "principalId": "f61fb52b-80c1-4adf-b9c4-0cc80c71d6d7",
            "tenantId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
            "type": "systemAssigned",
            "userAssignedIdentities": {
              "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
                "principalId": "1d34c2cd-bd53-487d-b3a9-6064465497c9",
                "clientId": "2071caa1-3668-4de3-babc-155cfe3e38e5"
              }
            }
          },
    },
    {
        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
        "name": "testregistry12543",
        "type": "Microsoft.ContainerRegistry/registries",
        "location": "eastus",
        "tags": {},
        "anonymousPullEnabled": false,
        "sku": {
            "name": "Premium",
            "tier": "Premium"
        },
        "policies": {
            "trustPolicy": {
              "type": "Notary",
              "status": "enabled"
            },
        },
    },
    {
        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
        "name": "testregistry12543",
        "type": "Microsoft.ContainerRegistry/registries",
        "location": "eastus",
        "tags": {},
        "anonymousPullEnabled": true,
        "sku": {
            "name": "Premium",
            "tier": "Premium"
        },
        "policies": {
            "trustPolicy": {
              "type": "Notary",
              "status": "disabled"
            },
        },
        "identity": {
            "principalId": "f61fb52b-80c1-4adf-b9c4-0cc80c71d6d7",
            "tenantId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
            "type": "systemAssigned, userAssigned",
            "userAssignedIdentities": {
              "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
                "principalId": "1d34c2cd-bd53-487d-b3a9-6064465497c9",
                "clientId": "2071caa1-3668-4de3-babc-155cfe3e38e5"
              }
            }
          },
    },

];
const createCache = (err, data) => {
    return {
        registries: {
            list: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('acrManagedIdentityEnabled', function() {
    describe('run', function() {
        it('should give passing result if no container registries', function(done) {
            const cache = createCache(null, []);
            acrManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing container registries found');
                expect(results[0].region).to.equal('eastus');
                done()
            });
        });

        it('should give failing result if container registry does not have managed identity enabled', function(done) {
            const cache = createCache(null,[registries[1]]);
            acrManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container registry does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            });

        });

        it('should give passing result if container registry has managed identity enabled', function(done) {
            const cache = createCache(null, [registries[0]]);
            acrManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container registry has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            });
        });

        it('should give passing result if container registry has both system and user assigned managed identity enabled', function(done) {
            const cache = createCache(null, [registries[2]]);
            acrManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container registry has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            });
        });

        it('should give passing result unable to query container registry', function(done) {
            const cache = createCache(null, null);
            acrManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for container registries:');
                expect(results[0].region).to.equal('eastus');
                done()
            });

        });
    });
});