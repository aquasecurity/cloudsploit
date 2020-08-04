var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./acrAdminUser');

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

describe('acrAdminUser', function() {
    describe('run', function() {
        it('should give passing result if no container registries', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing container registries found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if admin user is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Admin user is enabled on the container registry');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
                        "name": "testregistry12543",
                        "type": "Microsoft.ContainerRegistry/registries",
                        "location": "eastus",
                        "tags": {},
                        "sku": {
                            "name": "Basic",
                            "tier": "Basic"
                        },
                        "loginServer": "testregistry12543.azurecr.io",
                        "creationDate": "2019-10-18T21:16:01.347Z",
                        "provisioningState": "Succeeded",
                        "adminUserEnabled": true
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if admin user is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Admin user is not enabled on the container registry');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.ContainerRegistry/registries/testregistry12543",
                        "name": "testregistry12543",
                        "type": "Microsoft.ContainerRegistry/registries",
                        "location": "eastus",
                        "tags": {},
                        "sku": {
                            "name": "Basic",
                            "tier": "Basic"
                        },
                        "loginServer": "testregistry12543.azurecr.io",
                        "creationDate": "2019-10-18T21:16:01.347Z",
                        "provisioningState": "Succeeded",
                        "adminUserEnabled": false
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
});