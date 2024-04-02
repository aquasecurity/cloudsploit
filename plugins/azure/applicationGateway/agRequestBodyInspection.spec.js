var expect = require('chai').expect;
var agRequestBodyInspection = require('./agRequestBodyInspection.js');

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
            "mode": "prevention",
            "requestBodyCheck": true
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
        "enableDdosProtection": false,
        "policySettings":{
            "mode": "prevention",
            "requestBodyCheck": false
        }
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

describe('agRequestBodyInspection', function() {
    describe('run', function() {
        it('should give passing result if no WAF policy found', function(done) {
            const cache = createCache([]);
            agRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing WAF policies found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Application gateway WAF policy does not have request body inspection enabled', function(done) {
            const cache = createCache([wafPolicy[1]]);
            agRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application gateway WAF policy does not have request body inspection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give unknown result if Unable to query for WAF policy', function(done) {
            const cache = createErrorCache();
            agRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Gateway WAF policies');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application gateway WAF policy has request body inspection enabled', function(done) {
            const cache = createCache([wafPolicy[0]]);
            agRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Application gateway WAF policy has request body inspection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
}); 