var assert = require('assert');
var expect = require('chai').expect;
var acrPrivateEndpoints = require('./acrPrivateEndpoints');

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

describe('acrPrivateEndpoints', function() {
    describe('run', function() {
        it('should give passing result if no container registries', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container registries found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            acrPrivateEndpoints.run(cache, {}, callback);
        });

        it('should give failing result if private endpoints are not configured for container registery', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Private Endpoints are not configured for Container registry');
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
                        "adminUserEnabled": true,
                        "privateEndpointsConnections": [],
                        "publicNetworkAccess": "Enabled"
                    }
                ]
            );

            acrPrivateEndpoints.run(cache, {}, callback);
        });

        it('should give passing result if private endpoints are configured for container registry ', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private Endpoints are configured for Container registry');
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
                        "adminUserEnabled": false,
                        "privateEndpointConnections": [ 
                            {
                                "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.ContainerRegistry/registries/testregistry12543/privateEndpointConnections/test-endpoint",
                                'provisioningState': 'Succed'
                            }
                        ],
                        "publicNetworkAccess": "Disabled"
                    }
                ]
            );

            acrPrivateEndpoints.run(cache, {}, callback);
        })
    })

    it('should give unknown result if Unable to query for container registery', function(done) {
        const callback = (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include('Unable to query for container registries: ');
            expect(results[0].region).to.equal('eastus');
            done();
        };
        const cache = createCache({});

        acrPrivateEndpoints.run(cache, {}, callback);
    })
   
});