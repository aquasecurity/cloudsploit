var expect = require('chai').expect;
var javaVersion = require('./javaVersion');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1'
    }
];

const configurations = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'javaVersion': null
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'javaVersion': '1.8'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'javaVersion': '1.0'
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

describe('javaVersion', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([], []);
            javaVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no java app found', function(done) {
            const cache = createCache([webApps[0]], [configurations[0]]);
            javaVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No App Services with Java found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for app service', function(done) {
            const cache = createErrorCache('webApp');
            javaVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if app has no configs', function(done) {
            const cache = createErrorCache('configs');
            javaVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);

                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Service');

                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('No App Services with Java found');

                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app has latest java version', function(done) {
            const cache = createCache([webApps[0]], [configurations[1]]);
            javaVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Java version (1.8) is the latest version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service does not have latest java version', function(done) {
            const cache = createCache([webApps[0]], [configurations[2]]);
            javaVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Java version (1.0) is not the latest version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});