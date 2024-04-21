var expect = require('chai').expect;
var containerAppAuthenticationEnabled = require('./containerAppAuthEnabled');

const containerApps = [
    {
      "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test1",
      "name": "test1",
      "type": "Microsoft.App/containerApps",
      "identity": {
        "type": "SystemAssigned"
      }
    
      },
      {
        "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test2",
        "name": "test2",
        "type": "Microsoft.App/containerApps",
        "identity": {
            "type": "None"
        }
      },
];

const authConfig = [
    [ {
        "id": "/subscriptions/1234567/resourceGroups/test/providers/Microsoft.App/containerApps/test/authConfigs/current",
        "name": "current",
        "type": "Microsoft.App/containerapps/authconfigs",
        "platform": {
            "enabled": true
        },
        "globalValidation": {
            "unauthenticatedClientAction": "AllowAnonymous"
        },
        "identityProviders": {
            "customOpenIdConnectProviders": {}
        },
        "login": {
            "routes": {},
            "preserveUrlFragmentsForLogins": false,
            "allowedExternalRedirectUrls": [],
            "cookieExpiration": {},
            "nonce": {}
        }
        
    },
],
        
    [
        {

            "id": "/subscriptions/1234567/resourceGroups/test/providers/Microsoft.App/containerApps/test/authConfigs/current",
            "name": "current",
            "type": "Microsoft.App/containerapps/authconfigs",
            "platform": {
                "enabled": false
            },
            "globalValidation": {
                "unauthenticatedClientAction": "AllowAnonymous"
            },
            "identityProviders": {
                "customOpenIdConnectProviders": {}
            },
            "login": {
                "routes": {},
                "preserveUrlFragmentsForLogins": false,
                "allowedExternalRedirectUrls": [],
                "cookieExpiration": {},
                "nonce": {}
            }
        }
        
    ]

]




const createCache = (container, authConfig) => {
    const id = (container && container.length) ? container[0].id : null;
    return {
        containerApps: {
            list: {
                'eastus': {
                    data: container
                }
            },
            getAuthSettings: {
                'eastus': { 
                    [id]: { 
                        data: authConfig 
                    }
                }
            }
        }
    };
};


describe('containerAppAuthenticationEnabled', function() {
    describe('run', function() {
        it('should give passing result if no container apps', function(done) {
            const cache = createCache([], null);
            containerAppAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for container apps', function(done) {
            const cache = createCache(null, null);
            containerAppAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if container app has authentication enabled', function(done) {
            const cache = createCache([containerApps[0]], authConfig[0]);
            containerAppAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container app has built-in authentication enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if container app does not have authentication enabled', function(done) {
            const cache = createCache([containerApps[1]], authConfig[1]);
            containerAppAuthenticationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container app does not have built-in authentication enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});