var expect = require('chai').expect;
var endpointLoggingEnabled = require('./endpointLoggingEnabled');

const profiles = [
    {
        "id": "/subscriptions/234/resourcegroups/sadeedrg/providers/Microsoft.Cdn/profiles/test-profile",
        "type": "Microsoft.Cdn/profiles",
        "name": "test-profile",
        "location": "Global",
        "kind": "cdn",
        "tags": {},
        "sku": {
          "name": "Standard_Microsoft"
        },
        "properties": {
          "resourceState": "Active",
          "provisioningState": "Succeeded"
        }
    }
];

const endpoints = [
    {
        "id": "/subscriptions/234/resourcegroups/sadeedrg/providers/Microsoft.Cdn/profiles/test-profile/endpoints/test-end",
        "type": "Microsoft.Cdn/profiles/endpoints",
        "name": "test-end",
        "location": "Global",
        "tags": {},
        "hostName": "test-end.azureedge.net",
        "originHostHeader": "akhtar-test.azurewebsites.net",
        "originPath": null,
        "isCompressionEnabled": true,
        "isHttpAllowed": true,
        "isHttpsAllowed": true,
        "queryStringCachingBehavior": "IgnoreQueryString"
        
    }
];

const diagnosticSettings = [
    {
        "id": "/subscriptions/234/resourcegroups/sadeedrg/providers/microsoft.cdn/profiles/test-profile/endpoints/test-end/providers/microsoft.insights/diagnosticSettings/test-diagnostic",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "test-diagnostic",
        "location": null,
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/234/resourceGroups/akhtar-rg/providers/Microsoft.Storage/storageAccounts/akhtarrgdiag",
        "serviceBusRuleId": null,
        "workspaceId": null,
        "eventHubAuthorizationRuleId": null,
        "eventHubName": null,
        "metrics": [],
        "logs": [
          {
            "category": "CoreAnalytics",
            "categoryGroup": null,
            "enabled": true,
            "retentionPolicy": {
              "enabled": true,
              "days": 2
            }
          }
        ],
        "logAnalyticsDestinationType": null
    },
    {
        "id": "/subscriptions/234/resourcegroups/sadeedrg/providers/microsoft.cdn/profiles/test-profile/endpoints/test-end/providers/microsoft.insights/diagnosticSettings/test-diagnostic",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "test-diagnostic2",
        "location": null,
        "kind": null,
        "tags": null,
        "identity": null,
        "storageAccountId": "/subscriptions/234/resourceGroups/akhtar-rg/providers/Microsoft.Storage/storageAccounts/akhtarrgdiag",
        "serviceBusRuleId": null,
        "workspaceId": null,
        "eventHubAuthorizationRuleId": null,
        "eventHubName": null,
        "metrics": [],
        "logs": [],
        "logAnalyticsDestinationType": null
    }
]

const createCache = (profiles, endpoints, diagnostics) => {
    let containers = {};
    if (profiles.length) {
        containers[profiles[0].id] = {
            data : endpoints
        };
    }

    let diagnostic = {};
        if (endpoints.length) {
            diagnostic[endpoints[0].id] = {
                data: diagnostics
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
        endpoints: {
            listByProfile: {
                'global': containers
            }
        },
        diagnosticSettings:{
            listByEndpoint: {
                'global': diagnostic
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
    } else if (key === 'container') {
                return {
                    profiles: {
                        list: {
                            'global': {
                                data: [profiles[0]]
                            }
                        }
                    },
                    endpoints: {
                        listByProfile: {
                            'global': {}
                        }
                    }
                };
    } else {
        const profileId = (profiles && profiles.length) ? profiles[0].id : null;
        const endpointId = (endpoints && endpoints.length) ? endpoints[0].id : null;
        return {
            profiles: {
                list: {
                    'global': {
                        data: [profiles[0]]
                    }
                }
            },
            endpoints: {
                listByProfile: {
                    'global': {
                        [profileId]: {
                            data: [endpoints[0]]
                        }
                    }
                },
            },
            diagnosticSettings: {
                listByEndpoint: {
                    'global': {
                        data: {}
                    }
                }     
            }
        };
    }
};

describe('endpointLoggingEnabled', function() {
    describe('run', function() {
        it('should give passing result if No existing CDN profiles found', function(done) {
            const cache = createCache([], [], []);
            endpointLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing CDN profiles found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
        
        it('should give passing result if No existing CDN endpoints found', function(done) {
            const cache = createCache([profiles[0]], [], []);
            endpointLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing CDN endpoints found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query CDN profiles', function(done) {
            const cache = createErrorCache('profile');
            endpointLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query CDN profiles:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query CDN endpoints', function(done) {
            const cache = createErrorCache('container');
            endpointLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query CDN endpoints');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query diagnostics settings', function(done) {
            const cache = createErrorCache('policy');
            endpointLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query diagnostics settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if Request logging is enabled for endpoint', function(done) {
            const cache = createCache([profiles[0]], [endpoints[0]], [diagnosticSettings[0]]);
            endpointLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Request logging is enabled for endpoint');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if Request logging is not enabled for endpoint', function(done) {
            const cache = createCache([profiles[0]], [endpoints[0]], [diagnosticSettings[1]]);
            endpointLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Request logging is not enabled for endpoint');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});