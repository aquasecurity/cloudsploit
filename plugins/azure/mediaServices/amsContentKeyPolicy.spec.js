var expect = require('chai').expect;
var amsContentKeyPolicy = require('./amsContentKeyPolicy');

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

const listContentKeyPolicies = [
    {
        "name": "PolicyWithClearKeyOptionAndTokenRestriction",
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Media/mediaservices/test/contentKeyPolicies/PolicyWithClearKeyOptionAndTokenRestriction",
        "type": "Microsoft.Media/mediaservices/contentKeyPolicies",
        "properties": {
            "policyId": "8352435b-ebea-4681-aae7-e19277771f64",
            "created": "2017-12-01T00:00:00Z",
            "lastModified": "2017-11-01T00:00:00Z",
            "description": "A policy with one ClearKey option and Open Restriction."
        }
    }
];

const createCache = (ams, cp) => {
    const id = (ams && ams.length) ? ams[0].id : null;
    return {
        mediaServices: {
            listAll: {
                'eastus': {
                    data: ams
                }
            },
            listContentKeyPolicies: {
                'eastus': { 
                    [id]: { 
                        data: cp 
                    }
                }
            }
        },
    };
};

describe('amsContentKeyPolicy', function() {
    describe('run', function() {
        it('should give passing result if no media services found', function(done) {
            const cache = createCache([], null);
            amsContentKeyPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Media Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for media services', function(done) {
            const cache = createCache(null, null);
            amsContentKeyPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Media Services:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to get media service', function(done) {
            const cache = createCache([mediaServices[0]], null);
            amsContentKeyPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Content Key Policy for Media service account:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if content key policy exist', function(done) {
            const cache = createCache([mediaServices[0]], [listContentKeyPolicies[1]]);
            amsContentKeyPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Media Service account has content key policy configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if content key policy not exist', function(done) {
            const cache = createCache([mediaServices[0]], []);
            amsContentKeyPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Media Service account does not have content key policy configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});