var expect = require('chai').expect;
var lbNoInstances = require('./lbNoInstances');

const loadBalancers = [
    {
        "name": 'aqua-lb',
        "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb',
        "type": 'Microsoft.Network/loadBalancers',
        "location": 'eastus',
        "backendAddressPools": [
            {
                "name": 'aqua-bp',
                "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb/backendAddressPools/aqua-bp',
                "properties": {
                    "provisioningState": 'Succeeded',
                    "backendIPConfigurations": [
                        {
                            "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/networkInterfaces/aqua-instance/ipConfigurations/ipconfig1'
                        }
                    ]
                },
                "type": 'Microsoft.Network/loadBalancers/backendAddressPools'
            }
        ],
    },
    {
        "name": 'aqua-lb',
        "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb',
        "type": 'Microsoft.Network/loadBalancers',
        "location": 'eastus',
        "backendAddressPools": []
    }
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

describe('lbNoInstances', function() {
    describe('run', function() {
        it('should give passing result if no existing Load Balancers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Load Balancers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            lbNoInstances.run(cache, {}, callback);
        });

        it('should give passing result if Load Balancer has', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Load Balancer has 1 backend instance or address');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[0]]
            );

            lbNoInstances.run(cache, {}, callback);
        });

        it('should give failing result if Load Balancer does not have any backend instances', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Load Balancer does not have any backend instances');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[1]],
            );

            lbNoInstances.run(cache, {}, callback);
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

            lbNoInstances.run(cache, {}, callback);
        });
    })
});