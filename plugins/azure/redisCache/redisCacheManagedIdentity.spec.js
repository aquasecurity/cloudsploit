var expect = require('chai').expect;
var redisCacheManagedIdentity = require('./redisCacheManagedIdentity');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'tags': { "key": "value" },
        "identity": {
            "type": "SystemAssigned",
            "principalId": "1ca87ddb-6850-430d-9800-08be5b6b33bf",
            "tenantId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8"
          }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'tags': {},
    },

];

const createCache = (redisCaches) => {
    let caches = {};
    if (redisCaches) {
        caches['data'] = redisCaches;
    }
    return {
        redisCaches: {
            listBySubscription: {
                'eastus': caches
            }
        },
    };
};

describe('redisCacheManagedIdentity', function() {
    describe('run', function() {
        it('should give passing result if no redis caches', function(done) {
            const cache = createCache([]);
            redisCacheManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for redis caches', function(done) {
            const cache = createCache(null);
            redisCacheManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache has managed identity enabled associated', function(done) {
            const cache = createCache([redisCaches[0]]);
            redisCacheManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache does not have managed identity enabled', function(done) {
            const cache = createCache([redisCaches[1]]);
            redisCacheManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});