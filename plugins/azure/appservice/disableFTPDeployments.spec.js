var expect = require('chai').expect;
var disableFTPDeployments = require('./disableFTPDeployments');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1'
    }
];

const configurations = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'ftpsState': 'FtpsOnly'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'ftpsState': 'AllAllowed'
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

describe('disableFTPDeployments', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([], []);
            disableFTPDeployments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for app service', function(done) {
            const cache = createErrorCache('webApp');
            disableFTPDeployments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query app service', function(done) {
            const cache = createErrorCache('configs');
            disableFTPDeployments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Service');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app service has FTP deployments disabled', function(done) {
            const cache = createCache([webApps[0]], [configurations[0]]);
            disableFTPDeployments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('FTP deployments are disabled for this web app');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service does not have FTP deployments disabled', function(done) {
            const cache = createCache([webApps[0]], [configurations[1]]);
            disableFTPDeployments.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('FTP deployments are not disabled for this web app');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
