var expect = require('chai').expect;
var agHttp2Enabled = require('./agHttp2Enabled');

const appGateways = [
    {
        'name': 'test-ag',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-ag',
        'type': 'Microsoft.Network/applicationGateways',
        'location': 'eastus',
        'enableHttp2': true
    },
    {
        'name': 'test-ag',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-ag',
        'type': 'Microsoft.Network/applicationGateways',
        'location': 'eastus',
        'enableHttp2': false
    },
    {
        'name': 'test-ag',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-ag',
        'type': 'Microsoft.Network/applicationGateways',
        'location': 'eastus'
    }
];

const createCache = (appGateways) => {
    return {
        applicationGateway: {
            listAll: {
                'eastus': {
                    data: appGateways
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        applicationGateway: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('agHttp2Enabled', function () {
    describe('run', function () {
        it('should give passing result if no application gateways found', function (done) {
            const cache = createCache([]);
            agHttp2Enabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Application Gateway found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for application gateways', function (done) {
            const cache = createErrorCache();
            agHttp2Enabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Gateway');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if HTTP2 is enabled for application gateway', function (done) {
            const cache = createCache([appGateways[0]]);
            agHttp2Enabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('HTTP2 is enabled for Application Gateway');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if HTTP2 is not enabled for application gateway', function (done) {
            const cache = createCache([appGateways[1]]);
            agHttp2Enabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('HTTP2 is not enabled for Application Gateway');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if HTTP2 setting does not exist for application gateway', function (done) {
            const cache = createCache([appGateways[2]]);
            agHttp2Enabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('HTTP2 is not enabled for Application Gateway');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
