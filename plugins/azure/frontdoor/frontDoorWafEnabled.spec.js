var expect = require('chai').expect;
var frontDoorWafEnabled = require('./frontDoorWafEnabled.js');

const profiles = [
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/cloudsploit-dev/providers/Microsoft.Cdn/profiles/omer-cdn-profile-test",
        "type": "Microsoft.Cdn/profiles",
        "name": "omer-cdn-profile-test",
        "location": "Global",
        "kind": "frontdoor",
        "tags": {},
        "sku": {
          "name": "Standard_AzureFrontDoor"
        },
        "frontDoorId": "cd0e521b-8975-411d-b009-7db9de8f16a3",
        "resourceState": "Active",
        "provisioningState": "Succeeded"
    },
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/mehak-fd",
        "type": "Microsoft.Cdn/profiles",
        "name": "mehak-fd",
        "location": "Global",
        "kind": "frontdoor",
        "tags": {},
        "sku": {
          "name": "Premium_AzureFrontDoor"
        },
        "frontDoorId": "40590271-c2c4-4264-8061-45b884a91a70",
        "resourceState": "Active",
        "provisioningState": "Succeeded"
    },
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/meerab-test",
        "type": "Microsoft.Cdn/profiles",
        "name": "meerab-test",
        "location": "Global",
        "kind": "frontdoor",
        "tags": {},
        "sku": {
          "name": "Premium_AzureFrontDoor"
        },
        "frontDoorId": "7bc32535-6836-44ef-99fa-19dbdcf4dabf",
        "resourceState": "Active",
        "provisioningState": "Succeeded"
    },
];

const afdSecurityPolicies = [
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/meerab-test/securitypolicies/e9df717b-b2c0-4f37-9150-33d736402038",
        "type": "Microsoft.Cdn/profiles/securitypolicies",
        "name": "e9df717b-b2c0-4f37-9150-33d736402038",
        "parameters": {
          "wafPolicy": {
            "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoorwebapplicationfirewallpolicies/meerabpremiumtest"
          },
          "associations": [
            {
              "domains": [
                {
                  "isActive": true,
                  "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/Microsoft.Cdn/profiles/meerab-test/afdendpoints/test-meerab-runtime"
                }
              ],
              "patternsToMatch": [
                "/*"
              ]
            }
          ],
          "type": "WebApplicationFirewall"
        },
        "deploymentStatus": "NotStarted",
        "provisioningState": "Succeeded"
    }
]

const createCache = (profiles, securityPolicies) => {
    let securityPolicy = {};
    if (profiles.length) {
        securityPolicy[profiles[0].id] = {
            data: securityPolicies
        };
    }


    return {
        profiles: {
            list: {
                'global': {
                    data: profiles
                }
            }
        },
        afdSecurityPolicies: {
            listByProfile: {
                'global': securityPolicy
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'profile') {
        return {
            profiles: {
                list: {
                    'global': {}
                }
            }
        };
    } else if (key === 'noprofile'){
        return {
            profiles: {
                list: {
                    'global': {
                        data:{}
                    }
                }
            }
        };
    }else if (key === 'securityPolicy') {
        return {
            profiles: {
                list: {
                    'global': {
                        data: [profiles[0]]
                    }
                }
            },
            afdSecurityPolicies: {
                listByProfile: {
                    'global': {}
                }
            }
        };
    } else {
        const profileId = (profiles && profiles.length) ? profiles[1].id : null;
        const securityPolicy = (afdSecurityPolicies && afdSecurityPolicies.length) ? afdSecurityPolicies[0].id : null;
        return {
            profiles: {
                list: {
                    'global': {
                        data: [profiles[1]]
                    }
                }
            },
            afdSecurityPolicies: {
                listByProfile: {
                    'global': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('frontDoorWafEnabled', function () {
    describe('run', function () {

        it('should give pass result if No existing Azure Front Door profiles found', function (done) {
            const cache = createErrorCache('noprofile');
            frontDoorWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Front Door profiles found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query Front Door profiles:', function (done) {
            const cache = createErrorCache('profile');
            frontDoorWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Front Door profiles: ');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query security policies', function (done) {
            const cache = createErrorCache('policy');
            frontDoorWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Front Door security policies');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass result Front Door profile have waf enabled', function (done) {
            const cache = createCache([profiles[1]], [afdSecurityPolicies[0]]);
            frontDoorWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door profile has WAF enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if Front Door profile does not have waf enabled', function (done) {
            const cache = createCache([profiles[1]], []);
            frontDoorWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door profile does not have WAF enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

    });
});