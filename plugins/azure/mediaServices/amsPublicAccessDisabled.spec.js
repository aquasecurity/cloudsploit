var expect = require('chai').expect;
var amsPublicAccessDisabled = require('./amsPublicAccessDisabled');

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
    },
    {
        "name": 'test',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test',
        "type": 'Microsoft.Media/mediaservices',
        "location": 'eastus',
        "publicNetworkAccess": 'Disabled',
        "provisioningState": 'Succeeded',
        "privateEndpointConnections": [],
        "minimumTlsVersion": 'Tls12'
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

describe('amsPublicAccessDisabled', function() {
    describe('run', function() {
        it('should give passing result if no media services found', function(done) {
            const cache = createCache([]);
            amsPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Media Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for media services', function(done) {
            const cache = createCache(null);
            amsPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Media Services:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if public access disabled', function(done) {
            const cache = createCache([mediaServices[1]]);
            amsPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Media Service has public access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if public access enabled', function(done) {
            const cache = createCache([mediaServices[0]]);
            amsPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Media Service does not have public access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});