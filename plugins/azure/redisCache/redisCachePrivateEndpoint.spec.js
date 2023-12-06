var expect = require('chai').expect;
var plugin = require('./redisCachePrivateEndpoint');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'publicNetworkAccess': 'Disabled',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'publicNetworkAccess': 'Enabled',
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

describe('redisCachePrivateEndpoint', function() {
    describe('run', function() {
        it('should give passing result if there are no redis caches', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([]);

            plugin.run(cache, {}, callback);
        });
        
        it('should give unknown result if unable to query for redis caches', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(null);

            plugin.run(cache, {}, callback);
        });
        
        it('should give passing result if redis cache is only accessible through private endpoint', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache is only accessible through private endpoints');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([redisCaches[0]]);

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if redis cache is publicly accessible', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([redisCaches[1]]);

            plugin.run(cache, {}, callback);
        });
    })
})