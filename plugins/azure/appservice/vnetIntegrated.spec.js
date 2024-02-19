var expect = require('chai').expect;
var vnetIntegrated = require('./vnetIntegrated');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'virtualNetworkSubnetId': '/subscriptions/12345/resourceGroups/cloudsploit-dev/providers/Microsoft.Network/virtualNetworks/test/subnets/default'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/app1',
        'name': 'app1',
        'virtualNetworkSubnetId': null
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

describe('vnetIntegrated', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            vnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query web app ', function(done) {
            const cache = createErrorCache();
            vnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if app service has Vnet Integrated', function(done) {
            const cache = createCache([webApps[0]]);
            vnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service is integrated with a virtual network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if app service app service does not have Vnet Integrated', function(done) {
            const cache = createCache([webApps[1]]);
            vnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service is not integrated with a virtual network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});