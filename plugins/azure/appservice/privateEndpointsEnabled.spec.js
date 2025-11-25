var expect = require('chai').expect;
var privateEndpointsEnabled = require('./privateEndpointsEnabled');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'kind': 'app',
        'privateEndpointConnections': [
            {
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/privateEndpointConnections/test-endpoint',
                'name': 'test-endpoint'
            }
        ]
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app2',
        'name': 'app2',
        'kind': 'app',
        'privateEndpointConnections': []
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/func1',
        'name': 'func1',
        'kind': 'functionapp',
        'privateEndpointConnections': [
            {
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/func1/privateEndpointConnections/func-endpoint',
                'name': 'func-endpoint'
            }
        ]
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/func2',
        'name': 'func2',
        'kind': 'functionapp',
        'privateEndpointConnections': []
    }
];

const createCache = (webApps, privateEndpointConnections) => {
    let cache = {
        webApps: {
            list: {
                'eastus': {
                    data: webApps
                }
            }
        }
    };

    if (privateEndpointConnections && webApps) {
        cache.webApps.getWebAppDetails = {
            'eastus': {}
        };
        webApps.forEach((webApp, index) => {
            if (webApp && webApp.id) {
                cache.webApps.getWebAppDetails['eastus'][webApp.id] = {
                    data: {
                        ...webApp,
                        privateEndpointConnections: privateEndpointConnections[index] || []
                    }
                };
            }
        });
    }

    return cache;
};

const createErrorCache = () => {
    return {
        webApps: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('privateEndpointsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query web app ', function(done) {
            const cache = createErrorCache();
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app service has Private Endpoints configured', function(done) {
            const cache = createCache([webApps[0]], [[{id: 'endpoint1', name: 'test-endpoint'}]]);
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service has Private Endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service does not have Private Endpoints configured', function(done) {
            const cache = createCache([webApps[1]], [[]]);
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service does not have Private Endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if function app has Private Endpoints configured', function(done) {
            const cache = createCache([webApps[2]], [[{id: 'func-endpoint', name: 'func-test-endpoint'}]]);
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Function App has Private Endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if function app does not have Private Endpoints configured', function(done) {
            const cache = createCache([webApps[3]], [[]]);
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Function App does not have Private Endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});