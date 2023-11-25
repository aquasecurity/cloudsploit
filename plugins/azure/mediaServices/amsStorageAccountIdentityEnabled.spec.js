var expect = require('chai').expect;
var amsStorageAccountIdentityEnabled = require('./amsStorageAccountIdentityEnabled');

const mediaServices = [
    {
        "name": 'test',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test',
        "type": 'Microsoft.Media/mediaservices',
        "location": 'eastus',
        "publicNetworkAccess": 'Enabled',
        "provisioningState": 'Succeeded',
        "privateEndpointConnections": [],
        "minimumTlsVersion": 'Tls12',
        "storageAuthentication": "system"
    },
    {
        "name": 'test',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test',
        "type": 'Microsoft.Media/mediaservices',
        "location": 'eastus',
        "publicNetworkAccess": 'Disabled',
        "provisioningState": 'Succeeded',
        "privateEndpointConnections": [],
        "minimumTlsVersion": 'Tls12',
        "storageAuthentication": "ManagedIdentity"
    }
];

const createCache = (ams, ds) => {
    return {
        mediaServices: {
            listAll: {
                'eastus': {
                    data: ams
                }
            }
        }
    };
};

describe('amsStorageAccountIdentityEnabled', function() {
    describe('run', function() {
        it('should give passing result if no media services found', function(done) {
            const cache = createCache([]);
            amsStorageAccountIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Media Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for media services', function(done) {
            const cache = createCache(null);
            amsStorageAccountIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Media Services:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if storage account managed identity enabled for authentication', function(done) {
            const cache = createCache([mediaServices[1]]);
            amsStorageAccountIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Managed Identity is enabled for Azure Media Service storage authentication');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if system authentication enabled', function(done) {
            const cache = createCache([mediaServices[0]]);
            amsStorageAccountIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Managed Identity is not enabled for Azure Media Service storage authentication');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});