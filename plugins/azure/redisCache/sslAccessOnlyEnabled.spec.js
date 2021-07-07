var expect = require('chai').expect;
var sslAccessOnlyEnabled = require('./sslAccessOnlyEnabled');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'enableNonSslPort': false,
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'enableNonSslPort': true,
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

describe('sslAccessOnlyEnabled', function() {
    describe('run', function() {
        it('should give passing result if no redis caches', function(done) {
            const cache = createCache([]);
            sslAccessOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for redis caches', function(done) {
            const cache = createCache(null);
            sslAccessOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache is accessible through SSL only', function(done) {
            const cache = createCache([redisCaches[0]]);
            sslAccessOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SSL Access Only is enabled for Azure Cache for Redis');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache is using non SSL port', function(done) {
            const cache = createCache([redisCaches[1]]);
            sslAccessOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SSL Access Only is not enabled for Azure Cache for Redis');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});