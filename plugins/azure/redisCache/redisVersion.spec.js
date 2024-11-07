var expect = require('chai').expect;
var redisVersion = require('./redisVersion');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'redisVersion': '6.0',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'redisVersion': '5.1',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis'
    }
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

describe('redisVersion', function() {
    describe('run', function() {
        it('should give passing result if no redis caches', function(done) {
            const cache = createCache([]);
            redisVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for redis caches', function(done) {
            const cache = createCache(null);
            redisVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache is using latest redis version', function(done) {
            const cache = createCache([redisCaches[0]]);
            redisVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache is using the latest redis version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache is not using latest redis version', function(done) {
            const cache = createCache([redisCaches[1]]);
            redisVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache is not using the latest redis version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});