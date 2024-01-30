var expect = require('chai').expect;
var privateEndpointsEnabled = require('./privateEndpointsEnabled');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'privateLinkIdentifiers': '123456'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'privateLinkIdentifiers': ''
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
            const cache = createCache([webApps[0]]);
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service has Private Endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service app service does not have Private Endpoints configured', function(done) {
            const cache = createCache([webApps[1]]);
            privateEndpointsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service does not have Private Endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});