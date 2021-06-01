var expect = require('chai').expect;
var alwaysOnEnabled = require('./alwaysOnEnabled');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'app,linux',
        'location': 'East US'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'functionapp',
        'location': 'East US'
    }
];

const configs = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'location': 'East US',
        'alwaysOn': true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'location': 'East US',
        'alwaysOn': false
    }
];

const createCache = (webApps, configs) => {
    let app = {};
    let config = {};

    if (webApps) {
        app['data'] = webApps;
        if (webApps && webApps.length) {
            config[webApps[0].id] = {
                'data': configs
            };
        }
    }

    return {
        webApps: {
            list: {
                'eastus': app
            },
            listConfigurations: {
                'eastus': config
            }
        }
    };
};

describe('alwaysOnEnabled', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            alwaysOnEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createCache();
            alwaysOnEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if always on can not be configured', function(done) {
            const cache = createCache([webApps[1]], []);
            alwaysOnEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Always On feature can not be configured for the function App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give unknown result if no web app configs', function(done) {
            const cache = createCache([webApps[0]], []);
            alwaysOnEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web App Configs:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web app configs', function(done) {
            const cache = createCache([webApps[0]]);
            alwaysOnEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web App Configs:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if always on is enabled', function(done) {
            const cache = createCache([webApps[0]], [configs[0]]);
            alwaysOnEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Always On feature is enabled for the Web App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if always on is disabled', function(done) {
            const cache = createCache([webApps[0]], [configs[1]]);
            alwaysOnEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Always On feature is disabled for the Web App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 