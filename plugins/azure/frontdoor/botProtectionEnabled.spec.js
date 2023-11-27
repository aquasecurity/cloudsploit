var expect = require('chai').expect;
var botProtectionEnabled = require('./botProtectionEnabled.js');

const afdWafPolicies = [
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy2",
        "sku": {
          "name": "Premium_AzureFrontDoor"
        },
        "managedRules": {
          "managedRuleSets": [
            {
              "ruleSetType": "DefaultRuleSet",
              "ruleSetVersion": "preview-0.1",
              "ruleSetAction": null,
              "ruleGroupOverrides": [],
              "exclusions": []
            },
            {
              "ruleSetType": "Microsoft_BotManagerRuleSet",
              "ruleSetVersion": "1.0",
              "ruleSetAction": null,
              "ruleGroupOverrides": [],
              "exclusions": []
            }
          ]
        }
    },
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy1",
        "sku": {
          "name": "Premium_AzureFrontDoor"
        },
        "managedRules": {
          "managedRuleSets": [
            {
              "ruleSetType": "DefaultRuleSet",
              "ruleSetVersion": "preview-0.1",
              "ruleSetAction": null,
              "ruleGroupOverrides": [],
              "exclusions": []
            },
          ]
        }
    },
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy1",
        "sku": {
          "name": "Classic_AzureFrontDoor"
        },
        "managedRules": {
          "managedRuleSets": [
            {
              "ruleSetType": "DefaultRuleSet",
              "ruleSetVersion": "preview-0.1",
              "ruleSetAction": null,
              "ruleGroupOverrides": [],
              "exclusions": []
            },
          ]
        }
      },
];

const createCache = (afdWafPolicies) => {
    return {
        afdWafPolicies: {
            listAll: {
                'global': {
                    data: afdWafPolicies
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        afdWafPolicies: {
            listAll: {
                'global': {
                    data:{}
                }
            }
        }
    };
};
describe('botProtectionEnabled', function () {
    describe('run', function () {

        it('should give pass result if bot protection is enabled for front door waf policy', function (done) {
            const cache = createCache([afdWafPolicies[0]]);
            botProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door profile WAF policy has bot protection enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
        
        it('should give fail result if bot protection is not enabled for front door waf policy', function (done) {
            const cache = createCache([afdWafPolicies[1]]);
            botProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door profile WAF policy does not have bot protection enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass result if no existing front door waf policy found', function (done) {
            const cache = createErrorCache();
            botProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Front Door WAF policies found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

    });
});