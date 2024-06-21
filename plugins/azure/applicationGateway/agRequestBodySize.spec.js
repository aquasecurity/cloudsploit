var expect = require('chai').expect;
var agRequestBodySize = require('./agRequestBodySize.js');

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
            "requestBodyCheck": true,
            "maxRequestBodySizeInKb": 128
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
            "requestBodyCheck": true,
            "maxRequestBodySizeInKb": 800

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
            "requestBodyCheck": false,
            "maxRequestBodySizeInKb": 128

        }
    },
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

describe('agRequestBodySize', function() {
    describe('run', function() {
        it('should give passing result if no WAF policy found', function(done) {
            const cache = createCache([]);
            agRequestBodySize.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing WAF policies found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for WAF policy', function(done) {
            const cache = createErrorCache();
            agRequestBodySize.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Gateway WAF policies');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application gateway WAF policy has max request body size of 128 - without setting', function(done) {
            const cache = createCache([wafPolicy[0]]);
            agRequestBodySize.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Application gateway WAF policy has max request body size of 128 which is less than or equal to 128');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Application gateway WAF policy has max request body size greater than 500 - with setting', function(done) {
            const cache = createCache([wafPolicy[1]]);
            agRequestBodySize.run(cache, {max_request_body_size: 500}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application gateway WAF policy has max request body size of 800 which is greater than 500');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
}); 