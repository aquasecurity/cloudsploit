var expect = require('chai').expect;
var remoteDebuggingDisabled = require('./remoteDebuggingDisabled');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'app,linux',
        'location': 'East US'
    }
];

const configs = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'location': 'East US',
        'remoteDebuggingEnabled': false
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'location': 'East US',
        'remoteDebuggingEnabled': true
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

describe('remoteDebuggingDisabled', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            remoteDebuggingDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createCache();
            remoteDebuggingDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if no web app configs', function(done) {
            const cache = createCache([webApps[0]], []);
            remoteDebuggingDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web App Configs');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web app configs', function(done) {
            const cache = createCache([webApps[0]]);
            remoteDebuggingDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web App Configs:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if remote debugging is disabled', function(done) {
            const cache = createCache([webApps[0]], [configs[0]]);
            remoteDebuggingDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Remote debugging is disabled for web app');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if remote debugging is enabled', function(done) {
            const cache = createCache([webApps[0]], [configs[1]]);
            remoteDebuggingDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Remote debugging is enabled for web app');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});