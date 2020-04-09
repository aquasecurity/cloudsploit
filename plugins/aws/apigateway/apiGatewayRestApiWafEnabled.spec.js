var assert = require('assert');
var expect = require('chai').expect;
var apiGatewayWafEnabled = require('./apiGatewayRestApiWafEnabled.js')

const createCache = (gateways, stages) => {
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': {
                    data: gateways
                }
            },
            getStages: {
                'us-east-1': stages
            }
        },
    }
};

describe('apiGatewayWafEnabled', function () {
    describe('run', function () {
        it('should FAIL if passed Gateways without WAF attached', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "testId",
                        name: "stage"
                    }
                ],
                {
                    testId: {
                        data: {
                            item: [{
                                deploymentId: 'wfy9ux',
                                stageName: 'Prod',
                            }]
                    }
                }
            });

            apiGatewayWafEnabled.run(cache, {}, callback);
        })

        it('should PASS if given Gateways with WAF attached', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "testId",
                        name: "stage"
                    }
                ],
                {
                    testId: {
                        data: {
                            item: [{
                                deploymentId: 'wfy9ux',
                                stageName: 'Prod',
                                webAclArn: 'test'
                            }]
                    }
                }
            });

            apiGatewayWafEnabled.run(cache, {}, callback);
        })

        it('should PASS if no Gateways passed at all', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                done()
            };

            const cache = createCache([], []);

            apiGatewayWafEnabled.run(cache, {}, callback);
        })
    })
})
