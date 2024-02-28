var assert = require('assert');
var expect = require('chai').expect;
var acrTrustedServiceEnabled = require('./acrTrustedServiceEnabled');

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

describe('acrTrustedServiceEnabled', function() {
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

            acrTrustedServiceEnabled.run(cache, {}, callback);
        });

        it('should give failing result if trusted Microsoft Azure cloud services are not allowed to access the container registery', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Trusted Microsoft services are not allowed to access the Container registry');
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
                        "networkRuleBypassOptions": "None",
                        "publicNetworkAccess": "Enabled"
                    }
                ]
            );

            acrTrustedServiceEnabled.run(cache, {}, callback);
        });

        it('should give passing result if trusted Microsoft Azure cloud services are allowed to access the container registery', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Trusted Microsoft services are allowed to access the Container registry');
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
                        "publicNetworkAccess": "Disabled",
                        "networkRuleBypassOptions": "AzureServices",
                    }
                ]
            );

            acrTrustedServiceEnabled.run(cache, {}, callback);
        })
    })
});