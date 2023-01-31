var expect = require('chai').expect;
var agPreventionModeEnabled = require('./agPreventionModeEnabled');

const appGateway = [
    {   "sku": {
        "tier": "WAF_v2"
        },
        "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-gateway",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "webApplicationFirewallConfiguration": {
          "enabled": true,
          "firewallMode": "Prevention",
        },
    },
    {   
        "sku": {
        "tier": "WAF_v2"
        },
       "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "webApplicationFirewallConfiguration": {
          "enabled": true,
          "firewallMode": "Detection",
        },
    },
    {   
        "sku": {
        "tier": "STANDARD_V2"
        },
       "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "webApplicationFirewallConfiguration": {
          "enabled": true,
          "firewallMode": "Detection",
        },
    }
];

const createCache = (gt) => {
    return {
        applicationGateway: {
            listAll: {
                'eastus': {
                    data: gt
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        applicationGateway: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('agPreventionModeEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Application Gateway found', function(done) {
            const cache = createCache([]);
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Application Gateway found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Application Gateway waf prevention mode not enabled', function(done) {
            const cache = createCache([appGateway[1]]);
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Prevention mode not enabled for application gateway WAF policy');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Application Gateway', function(done) {
            const cache = createErrorCache();
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Gateway:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application Gateway has tags associated', function(done) {
            const cache = createCache([appGateway[0]]);
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Prevention mode enabled for application gateway WAF policy');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if tier for application gateway is not waf_v2', function(done) {
            const cache = createCache([appGateway[2]]);
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Prevention mode is not supported for WAF Standard v2 tier');
                expect(results[0].region).to.equal('eastus');
                done();
            });
       });
    });
}); 

