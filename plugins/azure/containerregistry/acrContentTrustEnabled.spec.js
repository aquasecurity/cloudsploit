var assert = require('assert');

var acrContentTrustEnabled = require('./acrContentTrustEnabled');

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
            "quarantinePolicy": {
              "status": "disabled"
            },
            "trustPolicy": {
              "type": "Notary",
              "status": "disabled"
            },
        }
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
            "quarantinePolicy": {
              "status": "disabled"
            },
            "trustPolicy": {
              "type": "Notary",
              "status": "enabled"
            },
        }
    }

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

describe('acrContentTrustEnabled', function() {
    describe('run', function() {
        it('should give passing result if no container registries', function(done) {
            const cache = createCache(null, []);
            acrContentTrustEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing container registries found');
                expect(results[0].region).to.equal('eastus');
                done()
            });
        });

        it('should give failing result if content trsut is not enabled for container registry', function(done) {
            const cache = createCache(null,[registries[0]]);
            acrContentTrustEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Content trsut is not enabled for container registry');
                expect(results[0].region).to.equal('eastus');
                done()
            });

        });

        it('should give passing result if content trsut is enabled for container registry', function(done) {
            const cache = createCache(null, [registries[1]]);
            acrContentTrustEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Content trsut is enabled for container registry');
                expect(results[0].region).to.equal('eastus');
                done()
            });
        });

        it('should give passing result unable to query container registry', function(done) {
            const cache = createCache(null, null);
            acrContentTrustEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for container registries:');
                expect(results[0].region).to.equal('eastus');
                done()
            });

        });

    })
});