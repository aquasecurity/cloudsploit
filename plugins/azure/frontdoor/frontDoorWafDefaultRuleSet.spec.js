var expect = require('chai').expect;
var frontDoorWafDefaultRuleSet = require('./frontDoorWafDefaultRuleSet.js');

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
                "ruleSetType": "Microsoft_DefaultRuleSet",
                "ruleSetVersion": "2.0",
                "ruleSetAction": "Block",
                "exclusions": []
              }
            ]
          },
        
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
                "ruleSetType": "Microsoft_DefaultRuleSet",
                "ruleSetVersion": "2.1",
                "ruleSetAction": "Block",
                "exclusions": []
              }
            ]
          },
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
                "ruleSetType": "Microsoft_DefaultRuleSet",
                "ruleSetVersion": "2.1",
                "ruleSetAction": "Log",
                "exclusions": []
              }
            ]
          },
    },
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy1",
        "sku": {
          "name": "Classic_AzureFrontDoor"
        },
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
                'global': 'err'
            }
        }
    };
};
describe('frontDoorWafDefaultRuleSet', function () {
    describe('run', function () {

        it('should give pass result front door waf policy has latest 2.1 default rule set configured with block action', function (done) {
            const cache = createCache([afdWafPolicies[1]]);
            frontDoorWafDefaultRuleSet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('default rule set configured with block action');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass result if no existing front door premium waf policy found', function (done) {
            const cache = createCache([]);
            frontDoorWafDefaultRuleSet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Front Door WAF policies found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if front door WAF policy does not have latest default rule set configured', function (done) {
            const cache = createCache([afdWafPolicies[0]]);
            frontDoorWafDefaultRuleSet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door WAF policy have default rule set configured with version less than');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if front door WAF policy have latest default rule set configured without block action', function (done) {
            const cache = createCache([afdWafPolicies[2]]);
            frontDoorWafDefaultRuleSet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door WAF policy has latest Microsoft_DefaultRuleSet: 2.1 default rule set configured with log');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result unable to query for Front Door WAF policie', function (done) {
            const cache = createErrorCache();
            frontDoorWafDefaultRuleSet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Front Door WAF policies');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

    });
});