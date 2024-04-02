var expect = require('chai').expect;
var applicationGatewayHasTags = require('./applicationGatewayHasTags');

const appGateway = [
    {
        "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test-gateway",',
        "type": "Microsoft.Network/applicationGateways",
        "tags": { "key": "value" },
        "location": "eastus",
    },
    {
       "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/applicationGateways/test",',
        "type": "Microsoft.Network/applicationGateways",
        "tags": {},
        "location": "eastus",
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

describe('applicationGatewayHasTags', function() {
    describe('run', function() {
        it('should give passing result if no Application Gateway found', function(done) {
            const cache = createCache([]);
            applicationGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing application gateways found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Application Gateway does not have tags associated', function(done) {
            const cache = createCache([appGateway[1]]);
            applicationGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application Gateway does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Application Gateway', function(done) {
            const cache = createErrorCache();
            applicationGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for application gateways:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application Gateway has tags associated', function(done) {
            const cache = createCache([appGateway[0]]);
            applicationGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Application Gateway has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 