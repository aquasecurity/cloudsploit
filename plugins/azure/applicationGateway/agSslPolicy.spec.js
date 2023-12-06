var expect = require('chai').expect;
var agSslPolicy = require('./agSslPolicy');

const appGateway = [
    {   "sku": {
        "tier": "WAF_v2"
        },
        "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-gateway",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "sslPolicy": {
            "policyType": "Predefined",
            "policyName": "AppGwSslPolicy20220101"
        },
    },
    {   
        "sku": {
        "tier": "WAF_v2"
        },
       "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "sslPolicy": {
            "policyType": "Predefined",
            "policyName": "AppGwSslPolicy20150101"
        },
    },
    {   "sku": {
        "tier": "WAF_v2"
        },
        "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-gateway",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "sslPolicy": {
            "policyType": "Custom",
            "minProtocolVersion": "TLSV1_3"
        },
    },
    {   "sku": {
        "tier": "WAF_v2"
        },
        "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-gateway",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "sslPolicy": {
            "policyType": "Custom",
            "minProtocolVersion": "TLSV13"
        },
    }
];

const createCache = (gt) => {
    return {
        applicationGateway: {
            listAll: {
                'eastus': {
                    data: gt
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

describe('agSslPolicy', function() {
    describe('run', function() {
        it('should give passing result if no Application Gateway found', function(done) {
            const cache = createCache([]);
            agSslPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Application Gateway found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Application Gateway is using ssl policy which does not supports minimum TLS version', function(done) {
            const cache = createCache([appGateway[1]]);
            agSslPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SSL policy which does not support latest TLS version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Application Gateway', function(done) {
            const cache = createErrorCache();
            agSslPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Gateway:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application Gateway is using ssl policy which supports minimum TLS version', function(done) {
            const cache = createCache([appGateway[0]]);
            agSslPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SSL policy which supports latest TLS version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application Gateway is using custom ssl policy which supports minimum TLS version', function(done) {
            const cache = createCache([appGateway[2]]);
            agSslPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SSL policy which supports latest TLS version');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Application Gateway is using tls version which cannot be parsed', function(done) {
            const cache = createCache([appGateway[3]]);
            agSslPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application Gateway TLS version cannot be parsed');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 

