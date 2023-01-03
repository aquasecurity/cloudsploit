var expect = require('chai').expect;
var lbHasTags = require('./lbHasTags');

const loadBalancers = [
    {
        "name": 'aqua-lb',
        "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb',
        "type": 'Microsoft.Network/loadBalancers',
        "location": 'eastus',
        "tags": { "key": "value" }
    },
    {
        "name": 'aqua-lb',
        "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb',
        "type": 'Microsoft.Network/loadBalancers',
        "location": 'eastus',
        "tags": {}
    },
];

const createCache = (lbs, err) => {
    return {
        loadBalancers: {
            listAll: {
                'eastus': {
                    err: err,
                    data: lbs
                }
            }
        }
    }
};

describe('lbHasTags', function() {
    describe('run', function() {
        it('should give passing result if no existing Load Balancers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Load Balancers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            lbHasTags.run(cache, {}, callback);
        });

        it('should give passing result if lb has tags associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Load Balancer has tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[0]]
            );

            lbHasTags.run(cache, {}, callback);
        });

        it('should give failing result if lb does not have tags associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Load Balancer does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[1]],
            );

            lbHasTags.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query Load Balancers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Load Balancers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [],
                { message: 'Unable to query Load Balancers'}
            );

            lbHasTags.run(cache, {}, callback);
        });
    })
});