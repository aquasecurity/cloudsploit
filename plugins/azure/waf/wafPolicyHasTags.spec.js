var expect = require('chai').expect;
var wafPolicyHasTags = require('./wafPolicyHasTags');

const wafPolicy = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
        "type": 'Microsoft.Network/waf',
        "tags": { "key": "value" },
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": true
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

describe('wafPolicyHasTags', function() {
    describe('run', function() {
        it('should give passing result if no WAF policy found', function(done) {
            const cache = createCache([]);
            wafPolicyHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing WAF policies found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if WAF policy does not have tags associated', function(done) {
            const cache = createCache([wafPolicy[1]]);
            wafPolicyHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WAF policy does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for WAF policy', function(done) {
            const cache = createErrorCache();
            wafPolicyHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for WAF policies:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if WAF policy has tags associated', function(done) {
            const cache = createCache([wafPolicy[0]]);
            wafPolicyHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WAF policy has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 