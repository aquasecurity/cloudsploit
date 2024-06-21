var assert = require('assert');
var expect = require('chai').expect;
var acrAnonymousPullAccessEnabled = require('./acrAnonymousPullAccessEnabled');

registries = [
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
        "anonymousPullEnabled": true,
        "publicNetworkAccess": "Enabled"
    },
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
        "anonymousPullEnabled": false,
        "publicNetworkAccess": "Disabled"
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

describe('acrAnonymousPullAccessEnabled', function() {
    describe('run', function() {
        it('should give passing result if no container registries', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing container registries found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null, []);
            acrAnonymousPullAccessEnabled.run(cache, {}, callback);
        });

        it('should give failing result if anonymous pull access is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Anonymous pull access is enabled for the container registry');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null,[registries[0]]);
            acrAnonymousPullAccessEnabled.run(cache, {}, callback);
        });

        it('should give passing result if anonymous pull access is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Anonymous pull access is not enabled for the container registry');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null, [registries[1]]);
            acrAnonymousPullAccessEnabled.run(cache, {}, callback);
        })
        it('should give passing result unable to query container registry', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for container registries:');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null, null);
            acrAnonymousPullAccessEnabled.run(cache, {}, callback);
        })
    })
});