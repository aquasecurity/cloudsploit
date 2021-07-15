var expect = require('chai').expect;
var minimumTlsVersion = require('./minimumTlsVersion');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'minimumTlsVersion': '1.2',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'minimumTlsVersion': '1.1',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'minimumTlsVersion': '1.0',
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

describe('minimumTlsVersion', function() {
    describe('run', function() {
        it('should give passing result if no redis caches', function(done) {
            const cache = createCache([]);
            minimumTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for redis caches', function(done) {
            const cache = createCache(null);
            minimumTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache is using latest TLS version', function(done) {
            const cache = createCache([redisCaches[0]]);
            minimumTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache is using the latest TLS Version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache is using latest TLS version 1.1', function(done) {
            const cache = createCache([redisCaches[1]]);
            minimumTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache is not using the latest TLS Version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache is using latest TLS version 1.0', function(done) {
            const cache = createCache([redisCaches[2]]);
            minimumTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache is not using the latest TLS Version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache is using default TLS version', function (done) {
            const cache = createCache([redisCaches[3]]);
            minimumTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache is using the default TLS Version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});