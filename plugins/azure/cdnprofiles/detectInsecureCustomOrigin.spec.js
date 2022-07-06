var expect = require('chai').expect;
var detectInsecureCustomOrigin = require('./detectInsecureCustomOrigin');

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
        
    },
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
        "isHttpAllowed": false,
        "isHttpsAllowed": true,
        "queryStringCachingBehavior": "IgnoreQueryString"
    
    },

];

const createCache = (profiles, endpoints) => {
    let containers = {};
    if (profiles.length) {
        containers[profiles[0].id] = {
            data : endpoints
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
    } else {
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
    }
};

describe('detectInsecureCustomOrigin', function() {
    describe('run', function() {
        it('should give passing result if No existing CDN Profiles found', function(done) {
            const cache = createCache([], []);
            detectInsecureCustomOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing CDN Profiles found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if CDN profile does not contain any endpoints', function(done) {
            const cache = createCache([profiles[0]], []);
            detectInsecureCustomOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CDN profile does not contain any endpoints');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query for CDN Profiles', function(done) {
            const cache = createErrorCache('profile');
            detectInsecureCustomOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for CDN Profiles');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if Unable to query for CDN Profile endpoints', function(done) {
            const cache = createErrorCache('blobContainer');
            detectInsecureCustomOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for CDN Profile endpoints');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if CDN profile endpoint does not allow insecure HTTP origin', function(done) {
            const cache = createCache([profiles[0]], [endpoints[1]]);
            detectInsecureCustomOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CDN profile endpoint does not allow insecure HTTP origin');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if CDN profile endpoint allows insecure HTTP origin', function(done) {
            const cache = createCache([profiles[0]], [endpoints[0]]);
            detectInsecureCustomOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('CDN profile endpoint allows insecure HTTP origin');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
}); 