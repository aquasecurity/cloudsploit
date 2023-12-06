var expect = require('chai').expect;
var frontDoorRequestBodyInspection = require('./frontDoorRequestBodyInspection.js');

const afdWafPolicies = [
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy2",
        "sku": {
          "name": "Premium_AzureFrontDoor"
        },
        "policySettings": {
            "enabledState": "Enabled",
            "mode": "Prevention",
            "redirectUrl": null,
            "customBlockResponseStatusCode": 403,
            "customBlockResponseBody": null,
            "requestBodyCheck": "Disabled"
          },
    },
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy1",
        "sku": {
          "name": "Premium_AzureFrontDoor"
        },
        "policySettings": {
            "enabledState": "Enabled",
            "mode": "Prevention",
            "redirectUrl": null,
            "customBlockResponseStatusCode": 403,
            "customBlockResponseBody": null,
            "requestBodyCheck": "Enabled"
          },

    },
    {
        "id": "/subscriptions/123456789/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/testpolicy2",
        "type": "Microsoft.Network/frontdoorwebapplicationfirewallpolicies",
        "name": "testpolicy1",
        "sku": {
          "name": "classic"
        },
        "policySettings": {
            "enabledState": "Enabled",
            "mode": "Prevention",
            "redirectUrl": null,
            "customBlockResponseStatusCode": 403,
            "customBlockResponseBody": null,
            "requestBodyCheck": "Enabled"
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
                'global': {
                    err: 'Unable to query'
                }
            }
        }
    };
};
describe('frontDoorRequestBodyInspection', function () {
    describe('run', function () {

        it('should give pass result if request body inspection is enabled for front door waf policy', function (done) {
            const cache = createCache([afdWafPolicies[1]]);
            frontDoorRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door WAF policy has request body inspection enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass result if no existing front door waf policy found', function (done) {
            const cache = createCache([]);
            frontDoorRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Front Door WAF policies found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if request body inspection is not enabled for front door waf policy', function (done) {
            const cache = createCache([afdWafPolicies[0]]);
            frontDoorRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door WAF policy does not have request body inspection enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for front door WAF policies', function (done) {
            const cache = createErrorCache();
            frontDoorRequestBodyInspection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Front Door WAF policies:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});