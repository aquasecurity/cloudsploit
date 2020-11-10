var expect = require('chai').expect;
var apigatewayWafEnabled = require('./apigatewayWafEnabled');

const getRestApis = [
    {
        "id": "98mjrkp8ia",
        "name": "PetStore",
        "description": "Your first API with Amazon API Gateway. This is a sample API that integrates via HTTP with our demo Pet Store endpoints",
        "createdDate": 1604621029,
        "apiKeySource": "HEADER",
        "endpointConfiguration": {
            "types": [
                "REGIONAL"
            ]
        }
    }
];

const getStages = [
    {
        "item": [
            {
                "deploymentId": "se8o93",
                "stageName": "dev",
                "cacheClusterEnabled": false,
                "cacheClusterStatus": "NOT_AVAILABLE",
                "methodSettings": {},
                "tracingEnabled": false,
                "createdDate": 1604621158,
                "lastUpdatedDate": 1604621158,
                "webAclArn": "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-waf/ca44237b-b1d8-46b2-abad-ada48c7f0894",
            }
        ]
    },
    {
        "item": [
            {
                "deploymentId": "se8o93",
                "stageName": "dev",
                "cacheClusterEnabled": false,
                "cacheClusterStatus": "NOT_AVAILABLE",
                "methodSettings": {},
                "tracingEnabled": false,
                "createdDate": 1604621158,
                "lastUpdatedDate": 1604621158,
            }
        ]
    }
];


const createCache = (apis, stages) => {
    if (apis && apis.length && apis[0].id) var restApiId = apis[0].id;
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': {
                    data: apis
                },
            },
            getStages: {
                'us-east-1': {
                    [restApiId]: {
                        data: stages
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': {
                    err: {
                        message: 'error getting API Gateway Rest APIs'
                    },
                },
            },
            getStages: {
                'us-east-1': {
                    err: {
                        message: 'error getting API Gateway Rest API Stages'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': null
            },
            getStages: {
                'us-east-1': null
            }
        }
    };
};

describe('apigatewayWafEnabled', function () {
    describe('run', function () {
        it('should PASS if API Gateway API has WAF enabled for all stages', function (done) {
            const cache = createCache([getRestApis[0]], getStages[0]);
            apigatewayWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if API Gateway API does not have WAF enabled for stages', function (done) {
            const cache = createCache([getRestApis[0]], getStages[1]);
            apigatewayWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if No API Gateway Rest API Stages found', function (done) {
            const cache = createCache([getRestApis[0]], []);
            apigatewayWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest APIs', function (done) {
            const cache = createErrorCache();
            apigatewayWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest API Stages', function (done) {
            const cache = createCache([getRestApis[0]], null);
            apigatewayWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get Rest APIs response is not found', function (done) {
            const cache = createNullCache();
            apigatewayWafEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});