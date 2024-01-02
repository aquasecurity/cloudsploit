var expect = require('chai').expect;
var acrManagedIdentityEnabled = require('./acrManagedIdentityEnabled');

registries = [
    {
        "id": "/subscriptions/123445/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
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
            "principalId": "1234",
            "tenantId": "1234009",
            "type": "systemAssigned",
            "userAssignedIdentities": {
              "/subscriptions/12343345/resourcegroups/meerab-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
                "principalId": "1234333345",
                "clientId": "1234333345"
              }
            }
          },
    },
    {
        "id": "/subscriptions/123445/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
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
        "id": "/subscriptions/123445/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
        "name": "testregistry12543",
        "type": "Microsoft.ContainerRegistry/registries",
        "location": "eastus",
        "tags": {},
        "anonymousPullEnabled": true,
        "sku": {
            "name": "Basic",
            "tier": "Basic"
        },
        "policies": {
            "trustPolicy": {
              "type": "Notary",
              "status": "enabled"
            },
        },
        "identity": {
            "principalId": "1234",
            "tenantId": "1234009",
            "type": "systemAssigned, userAssigned",
            "userAssignedIdentities": {
              "/subscriptions/12343345/resourcegroups/meerab-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
                "principalId": "1234333345",
                "clientId": "1234333345"
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