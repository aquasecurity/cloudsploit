var expect = require('chai').expect;
var wafPolicyBotProtection = require('./wafPolicyBotProtection');

const wafPolicies = [
    {
        'name': 'test-policy',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/test-policy',
        'type': 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
        'location': 'eastus',
        'managedRules': {
            'managedRuleSets': [
                {
                    'ruleSetType': 'OWASP',
                    'ruleSetVersion': '3.2'
                },
                {
                    'ruleSetType': 'Microsoft_BotManagerRuleSet',
                    'ruleSetVersion': '1.0'
                }
            ]
        }
    },
    {
        'name': 'test-policy',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/test-policy',
        'type': 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
        'location': 'eastus',
        'managedRules': {
            'managedRuleSets': [
                {
                    'ruleSetType': 'OWASP',
                    'ruleSetVersion': '3.2'
                }
            ]
        }
    },
    {
        'name': 'test-policy',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/test-policy',
        'type': 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
        'location': 'eastus',
        'managedRules': {
            'managedRuleSets': [
                {
                    'ruleSetType': 'Microsoft_BotManagerRuleSet',
                    'ruleSetVersion': '1.0',
                    'ruleGroupOverrides': [
                        {
                            'ruleGroupName': 'BadBots',
                            'rules': [
                                {
                                    'ruleId': 'Bot100100',
                                    'state': 'Disabled'
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    },
    {
        'name': 'test-policy',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/test-policy',
        'type': 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
        'location': 'eastus'
    }
];

const createCache = (wafPolicies) => {
    return {
        wafPolicies: {
            listAll: {
                'eastus': {
                    data: wafPolicies
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

describe('wafPolicyBotProtection', function () {
    describe('run', function () {
        it('should give passing result if no WAF policies found', function (done) {
            const cache = createCache([]);
            wafPolicyBotProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing WAF policies found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for WAF policies', function (done) {
            const cache = createErrorCache();
            wafPolicyBotProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for WAF policies');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if WAF policy has bot protection enabled', function (done) {
            const cache = createCache([wafPolicies[0]]);
            wafPolicyBotProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WAF policy has bot protection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if WAF policy does not have bot manager rule set', function (done) {
            const cache = createCache([wafPolicies[1]]);
            wafPolicyBotProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WAF policy does not have bot protection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if WAF policy has malicious bot rules disabled', function (done) {
            const cache = createCache([wafPolicies[2]]);
            wafPolicyBotProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WAF policy has malicious bot rules disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if WAF policy does not have managed rules', function (done) {
            const cache = createCache([wafPolicies[3]]);
            wafPolicyBotProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WAF policy does not have bot protection enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
