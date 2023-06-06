var expect = require('chai').expect;
var agPreventionModeEnabled = require('./agPreventionModeEnabled.js');

const wafPolicy = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
        "type": 'Microsoft.Network/waf',
        "tags": { "key": "value" },
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": true,
        "policySettings":{
            "mode": "prevention"
        }
    },
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
        "type": 'Microsoft.Network/waf',
        "tags": {},
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": false
    }
];

const createCache = (waf) => {
    return {
        wafPolicies: {
            listAll: {
                'eastus': {
                    data: waf
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        wafPolicies: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('agPreventionModeEnabled', function() {
    describe('run', function() {
        it('should give passing result if no WAF policy found', function(done) {
            const cache = createCache([]);
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing WAF policies found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if application gateway WAF Policy prevention mode not enabled', function(done) {
            const cache = createCache([wafPolicy[1]]);
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Prevention mode not enabled for application gateway WAF policy');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give unknown result if Unable to query for WAF policy', function(done) {
            const cache = createErrorCache();
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Gateway WAF policies');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application Gateway WAF policy prevention mode enabled', function(done) {
            const cache = createCache([wafPolicy[0]]);
            agPreventionModeEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Prevention mode enabled for application gateway WAF policy');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
}); 