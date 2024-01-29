var expect = require('chai').expect;
var redisCacheVNetIntegrated = require('./redisCacheVNetIntegrated');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'redisCacheVNetIntegrated': '1.2',
        'sku':{
            'name':'Basic'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'redisCacheVNetIntegrated': '1.1',
        'sku':{
            'name':'Premium'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'redisCacheVNetIntegrated': '1.1',
        'sku':{
            'name':'Premium'
        },
        'subnetId': '/subscriptions/123/resourceGroups/aqua/providers/Microsoft.Network/virtualNetworks/aqua/subnets/aqua'
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

describe('redisCacheVNetIntegrated', function() {
    describe('run', function() {
        it('should give passing result if no redis caches', function(done) {
            const cache = createCache([]);
            redisCacheVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for redis caches', function(done) {
            const cache = createCache(null);
            redisCacheVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache has Vnet integrated', function(done) {
            const cache = createCache([redisCaches[2]]);
            redisCacheVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache has VNet integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache does not have Vnet integrated', function(done) {
            const cache = createCache([redisCaches[1]]);
            redisCacheVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache does not have VNet integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache is not premium', function(done) {
            const cache = createCache([redisCaches[0]]);
            redisCacheVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VNet Integration is only available for premium tier Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});