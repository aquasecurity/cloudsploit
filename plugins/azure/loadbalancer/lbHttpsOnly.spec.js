var expect = require('chai').expect;
var lbHttpsOnly = require('./lbHttpsOnly');

const loadBalancers = [
    {
        "name": 'aqua-lb',
        "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb',
        "type": 'Microsoft.Network/loadBalancers',
        "location": 'eastus',
        "inboundNatRules": [
            {
                "name": 'testHTTPSRule',
                "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb/inboundNatRules/testRule1',
                "type": 'Microsoft.Network/loadBalancers/inboundNatRules',
                "properties": {
                    "frontendPort": 443,
                    "backendPort": 443,
                }
            }
        ],
    },
    {
        "name": 'aqua-lb',
        "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb',
        "type": 'Microsoft.Network/loadBalancers',
        "location": 'eastus',
        "inboundNatRules": [
            {
                "name": 'testHTTPSRule',
                "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb/inboundNatRules/testRule1',
                "type": 'Microsoft.Network/loadBalancers/inboundNatRules',
                "properties": {
                    "frontendPort": 443,
                    "backendPort": 443,
                }
            },
            {
                "name": 'testHTTPSRule',
                "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb/inboundNatRules/testRule2',
                "type": 'Microsoft.Network/loadBalancers/inboundNatRules',
                "properties": {
                    "frontendPort": 444,
                    "backendPort": 444,
                }
            }
        ],
    },
    {
        "name": 'aqua-lb',
        "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb',
        "type": 'Microsoft.Network/loadBalancers',
        "location": 'eastus',
        "inboundNatRules": [
            {
                "name": 'testHTTPSRule',
                "id": '/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/loadBalancers/aqua-lb/inboundNatRules/testRule2',
                "type": 'Microsoft.Network/loadBalancers/inboundNatRules',
                "properties": {
                    "frontendPort": 444,
                    "backendPort": 444,
                }
            }
        ],
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

describe('lbHttpsOnly', function() {
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

            lbHttpsOnly.run(cache, {}, callback);
        });

        it('should give passing result if only HTTPS is configured', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Only HTTPS is configured');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[0]]
            );

            lbHttpsOnly.run(cache, {}, callback);
        });

        it('should give failing result if HTTPS is configured but other ports are open', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('HTTPS is configured but other ports are open');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[1]],
            );

            lbHttpsOnly.run(cache, {}, callback);
        });

        it('should give failing result if HTTPS is not configured and other ports are open', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('HTTPS is not configured and other ports are open');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[2]],
            );

            lbHttpsOnly.run(cache, {}, callback);
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

            lbHttpsOnly.run(cache, {}, callback);
        });
    })
});