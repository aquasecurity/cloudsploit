var expect = require('chai').expect;
var frontDoorWafDefaultRateLimit = require('./frontDoorWafDefaultRateLimit.js');

const afdWafPolicies = [
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy2",
        "sku": {
          "name": "Premium_AzureFrontDoor"
        },
        "customRules": {
            "rules": [
              {
                "name": "testcustomrule",
                "enabledState": "Enabled",
                "priority": 1,
                "ruleType": "RateLimitRule",
                "rateLimitDurationInMinutes": 0,
                "rateLimitThreshold": 0,
                "matchConditions": [
                  {
                    "matchVariable": "SocketAddr",
                    "selector": null,
                    "operator": "GeoMatch",
                    "negateCondition": false,
                    "matchValue": [
                      "PK"
                    ],
                    "transforms": []
                  }
                ],
                "action": "Block"
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
        "customRules": {
            "rules": [
              {
                "name": "testcustomrule",
                "enabledState": "Enabled",
                "priority": 1,
                "ruleType": "MatchRule",
                "rateLimitDurationInMinutes": 0,
                "rateLimitThreshold": 0,
                "matchConditions": [
                  {
                    "matchVariable": "SocketAddr",
                    "selector": null,
                    "operator": "GeoMatch",
                    "negateCondition": false,
                    "matchValue": [
                      "PK"
                    ],
                    "transforms": []
                  }
                ],
                "action": "Block"
              }
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
        "customRules": {
            "rules": [
              {
                "name": "testcustomrule",
                "enabledState": "Enabled",
                "priority": 1,
                "ruleType": "MatchRule",
                "rateLimitDurationInMinutes": 0,
                "rateLimitThreshold": 0,
                "matchConditions": [
                  {
                    "matchVariable": "SocketAddr",
                    "selector": null,
                    "operator": "GeoMatch",
                    "negateCondition": false,
                    "matchValue": [
                      "PK"
                    ],
                    "transforms": []
                  }
                ],
                "action": "Block"
              }
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
                'global': 'err'
            }
        }
    };
};
describe('frontDoorWafDefaultRateLimit', function () {
    describe('run', function () {

        it('should give pass result front door waf policy has rate limit custom rule configured', function (done) {
            const cache = createCache([afdWafPolicies[0]]);
            frontDoorWafDefaultRateLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door WAF policy has rate limit custom rule configured');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass result if no existing front door premium waf policy found', function (done) {
            const cache = createCache([]);
            frontDoorWafDefaultRateLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Front Door WAF policies found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if front door WAF policy does not have rate limit custom rule configured', function (done) {
            const cache = createCache([afdWafPolicies[1]]);
            frontDoorWafDefaultRateLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door WAF policy does not have rate limit custom rule configured');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result unable to query for Front Door WAF policie', function (done) {
            const cache = createErrorCache();
            frontDoorWafDefaultRateLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Front Door WAF policies');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

    });
});