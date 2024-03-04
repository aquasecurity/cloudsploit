var expect = require('chai').expect;
var accessControlAllowCredential = require('./accessControlAllowCredential');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'kind': 'app'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'kind': 'app,linux'
    }
];

const configurations = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'cors': {
            'allowedOrigins' :[
                'https://portal.azure.com'
            ],
            'supportedCredentials':true
        }
        
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1/config/web',
        'cors': {
            'allowedOrigins' :[
                'https://portal.azure.com'
            ],
            'supportedCredentials':false
        }
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

describe('accessControlAllowCredential', function() {
    describe('run', function() {
        it('should give passing result if no app service found', function(done) {
            const cache = createCache([], []);
            accessControlAllowCredential.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for app service', function(done) {
            const cache = createErrorCache('webApp');
            accessControlAllowCredential.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Service: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app has Access Control Allow Credentials enabled', function(done) {
            const cache = createCache([webApps[0]], [configurations[0]]);
            accessControlAllowCredential.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service has Access Control Allow Credentials enabled with CORS');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service does not have Access Control Allow Credentials enabled', function(done) {
            const cache = createCache([webApps[0]], [configurations[1]]);
            accessControlAllowCredential.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service does not have Access Control Allow Credentials enabled with CORS');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        
    });
});