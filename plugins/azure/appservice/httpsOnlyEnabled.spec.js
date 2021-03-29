var expect = require('chai').expect;
var httpsOnlyEnabled = require('./httpsOnlyEnabled');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'httpsOnly': true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'httpsOnly': false
    }
];

const createCache = (webApps) => {
    return {
        webApps: {
            list: {
                'eastus':{
                    data: webApps
                }
            }
        }
    };
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

describe('httpsOnlyEnabled', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            httpsOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query app service', function(done) {
            const cache = createErrorCache();
            httpsOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Service');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app service has HTTPS only enabled', function(done) {
            const cache = createCache([webApps[0]]);
            httpsOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The App Service has HTTPS Only enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service does not have HTTPS only enabled', function(done) {
            const cache = createCache([webApps[1]]);
            httpsOnlyEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The App Service does not have HTTPS Only enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});