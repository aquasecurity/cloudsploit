var expect = require('chai').expect;
var appServiceAccessRestriction = require('./appServiceAccessRestriction');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1'
    }
];

const configurations = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'ipSecurityRestrictions': [
            {
              'ipAddress': 'Any',
              'action': 'Allow',
              'priority': 1,
              'name': 'Allow all',
              'description': 'Allow all access'
            }
        ],
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'ipSecurityRestrictions': [ 
            {
                'ipAddress': '208.130.0.0/16',
                'action': 'Allow',
                'tag': 'Default',
                'priority': 1,
                'name': 'xyz'
            },
            {
                'ipAddress': 'Any',
                'action': 'Deny',
                'priority': 2147483647,
                'name': 'Deny all',
                'description': 'Deny all access'
            }
        ]
    }
];

const createCache = (webApps, configurations) => {
    let configs = {};
    if (webApps.length > 0) {
        configs[webApps[0].id] = {
            data: configurations
        };
    }
    return {
        webApps: {
            list: {
                'eastus': {
                    data: webApps
                }
            },
            listConfigurations: {
                'eastus': configs
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key === 'webApp') {
        return {
            webApps: {
                list: {
                    'eastus': {}
                }
            }
        };
    } else {
        return {
            webApps: {
                list: {
                    'eastus': {
                        data: [webApps[0]]
                    }
                },
                listConfigurations: {
                    'eastus': {}
                }
            }
        };
    }
};

describe('appServiceAccessRestriction', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([], []);
            appServiceAccessRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for app service', function(done) {
            const cache = createErrorCache('webApp');
            appServiceAccessRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if app has no configs', function(done) {
            const cache = createErrorCache('configs');
            appServiceAccessRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Service configuration');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app Service has access restriction enabled', function(done) {
            const cache = createCache([webApps[0]], [configurations[1]]);
            appServiceAccessRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service has access restriction enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if App Service does not have access restriction enabled', function(done) {
            const cache = createCache([webApps[0]], [configurations[0]]);
            appServiceAccessRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service does not have access restriction enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});