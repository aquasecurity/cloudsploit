var expect = require('chai').expect;
var nodeJsVersion = require('./nodeJsVersion');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1'
    }
];


const configurations = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'linuxFxVersion': '',
        'nodeVersion': '',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'linuxFxVersion': '',
        'nodeVersion': '~20',
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

describe('nodeJsVersion', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([], []);
            nodeJsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no Node.js app found', function(done) {
            const cache = createCache([webApps[0]], [configurations[0]]);
            nodeJsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No App Services with Node.js found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for app service', function(done) {
            const cache = createErrorCache('webApp');
            nodeJsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app has latest Node.js version', function(done) {
            const cache = createCache([webApps[0]], [configurations[1]]);
            nodeJsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Node.js version (20) is the latest version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        it('should give passing result if Linux app has latest Node.js version', function(done) {
            const cache = createCache([webApps[0]], [configurations[2]]);
            nodeJsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Node.js version (20) is the latest version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service does not have latest Node.js version', function(done) {
            const cache = createCache([webApps[0]], [configurations[3]]);
            nodeJsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Node.js version (18) is not the latest version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});