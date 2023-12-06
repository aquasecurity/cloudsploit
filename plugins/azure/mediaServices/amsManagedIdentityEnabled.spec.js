var expect = require('chai').expect;
var amsManagedIdentityEnabled = require('./amsManagedIdentityEnabled');

const mediaServices = [
    {
        "name": 'test',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test',
        "type": 'Microsoft.Media/mediaservices',
        "location": 'eastus',
        "publicNetworkAccess": 'Enabled',
        "provisioningState": 'Succeeded',
        "privateEndpointConnections": [],
        "minimumTlsVersion": 'Tls12'
    }
];

const getMediaService = [
    {
        "name": 'test',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test',
        "type": 'Microsoft.Media/mediaservices',
        "location": 'eastus',
        "publicNetworkAccess": 'Enabled',
        "provisioningState": 'Succeeded',
        "privateEndpointConnections": [],
        "minimumTlsVersion": 'Tls12'
    },
    {
        "name": 'test',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test',
        "type": 'Microsoft.Media/mediaservices',
        "location": 'eastus',
        "publicNetworkAccess": 'Enabled',
        "provisioningState": 'Succeeded',
        "privateEndpointConnections": [],
        "minimumTlsVersion": 'Tls12',
        "identity": {
            "type": "UserAssigned",
        }
    }
];

const createCache = (ams, ds) => {
    const id = (ams && ams.length) ? ams[0].id : null;
    return {
        mediaServices: {
            listAll: {
                'eastus': {
                    data: ams
                }
            },
            get: {
                'eastus': { 
                    [id]: { 
                        data: ds 
                    }
                }
            }
        },
    };
};

describe('amsManagedIdentityEnabled', function() {
    describe('run', function() {
        it('should give passing result if no media services found', function(done) {
            const cache = createCache([], null);
            amsManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Media Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for media services', function(done) {
            const cache = createCache(null, null);
            amsManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Media Services:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to get media service', function(done) {
            const cache = createCache([mediaServices[0]], null);
            amsManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Media Service');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if managed identity is not enabled', function(done) {
            const cache = createCache([mediaServices[0]], getMediaService[0]);
            amsManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Media Service account does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if classic API enabled', function(done) {
            const cache = createCache([mediaServices[0]], getMediaService[1]);
            amsManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Media Service account has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});