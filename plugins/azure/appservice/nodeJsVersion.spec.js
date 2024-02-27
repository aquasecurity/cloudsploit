var expect = require('chai').expect;
var pythonVersion = require('./nodeJsVersion');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1'
    }
];

const configurations = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'linuxFxVersion': ''
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'linuxFxVersion': 'NODE|20-lts'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'linuxFxVersion': 'NODE|18-lts'
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

describe('pythonVersion', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([], []);
            pythonVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no NodeJs app found', function(done) {
            const cache = createCache([webApps[0]], [configurations[0]]);
            pythonVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No App Services with NodeJs found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for app service', function(done) {
            const cache = createErrorCache('webApp');
            pythonVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app has latest NodeJs version', function(done) {
            const cache = createCache([webApps[0]], [configurations[1]]);
            pythonVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The NodeJs version (20-lts) is the latest version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service does not have latest NodeJs version', function(done) {
            const cache = createCache([webApps[0]], [configurations[2]]);
            pythonVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The NodeJs version (18-lts) is not the latest version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});