var expect = require('chai').expect;
var secureHttptriggerFunction = require('./secureHttptriggerFunction');

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

const functions = [
    {
       'config': {
            'bindings': [
                {
                    'authLevel': 'function',
                    'type': 'httpTrigger'
                }
            ]
           
        }
       
    },
    {

       'config': {
        'bindings': [
            {
                'authLevel': 'anonymous',
                'type': 'httpTrigger'
            }
        ]
       
    }
    }
];

const createCache = (webApps, functions) => {
    let app = {};
    let func = {};

    if (webApps) {
        app['data'] = webApps;
        if (webApps && webApps.length) {
            func[webApps[0].id] = {
                'data': functions
            };
        }
    }

    return {
        webApps: {
            list: {
                'eastus': app
            }
        },
        functions:{
            list:{
                'eastus': func
            }
        }
    };
};

describe('secureHttptriggerFunction', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            secureHttptriggerFunction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Service found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createCache();
            secureHttptriggerFunction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if http trigger funtions can not be configured', function(done) {
            const cache = createCache([webApps[0]], []);
            secureHttptriggerFunction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Http triggered functions can not be configured for web app');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if no http trigger function', function(done) {
            const cache = createCache([webApps[1]], []);
            secureHttptriggerFunction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Functions found for App Service');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for http trigger function', function(done) {
            const cache = createCache([webApps[1]]);
            secureHttptriggerFunction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Azure Functions for app service: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if auth level is function for http trigger function', function(done) {
            const cache = createCache([webApps[1]], [functions[0]]);
            secureHttptriggerFunction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('HTTP triggered function has secured authorization Level');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if auth level is not function for http trigger function', function(done) {
            const cache = createCache([webApps[1]], [functions[1]]);
            secureHttptriggerFunction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('HTTP triggered function does not have secured authorization Level');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 