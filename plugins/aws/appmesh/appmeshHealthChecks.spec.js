const expect = require('chai').expect;
var appmeshHealthChecks = require('./appmeshHealthChecks');

const describeVirtualGateways = {
    virtualGateways: [
        {
            virtualGatewayName: 'vg-1',
            arn: 'arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh1/virtualGateway/vg-1',
            spec: {
                listeners: [
                    {
                        healthCheck: {
                            protocol: 'http',
                            healthyThreshold: 2,
                            intervalMillis: 30000,
                            timeoutMillis: 2000,
                            unhealthyThreshold: 3
                        }
                    }
                ]
            }
        },
        {
            virtualGatewayName: 'vg-2',
            arn: 'arn:aws:appmesh:us-east-1:000011112222:mesh/sadeed-mesh2/virtualGateway/vg-2',
            spec: {
                listeners: []
            }
        }
    ]
};

const createCache = (describeVirtualGateways, describeVirtualGatewaysErr) => {
    return {
        appmesh: {
            listVirtualGateways: {
                'us-east-1': {
                    err: describeVirtualGatewaysErr,
                    data: {
                        "virtualGateways": describeVirtualGateways
                    }
                }
            },
            describeVirtualGateway: {
                'us-east-1': {
                    'vg-1': {
                        err: null,
                        data: {
                            virtualGateway: describeVirtualGateways[0]
                        }
                    },
                    'vg-2': {
                        err: null,
                        data: {
                            virtualGateway: describeVirtualGateways[1]
                        }
                    }
                }
            },
        },
    };
};

describe('appmeshHealthChecks', function () {
    describe('run', function () {
        it('should PASS if App Mesh virtual gateways have health check policies', function (done) {
            const cache = createCache([describeVirtualGateways.virtualGateways[0]]);
            appmeshHealthChecks.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('App Mesh virtual gateway has health check policies');
                done();
            });
        });

        it('should FAIL if App Mesh virtual gateways do not have health check policies', function (done) {
            const cache = createCache([describeVirtualGateways.virtualGateways[1]]);
            appmeshHealthChecks.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('App Mesh virtual gateway does not have health check policies');
                done();
            });
        });
    });
});
