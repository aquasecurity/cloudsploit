var expect = require('chai').expect;
var apigatewayResponseCaching = require('./apigatewayResponseCaching');

const getRestApis = [
    {
        "id": "mr5lhq7we8",
        "name": "FoodLeaStack",
        "createdDate": "2022-02-25T17:26:23+05:00",
        "version": "1.0",
        "apiKeySource": "HEADER",
        "endpointConfiguration": {
            "types": [
                "EDGE"
            ]
        },
        "tags": {
            "AWSServerlessAppNETCore": "true",
            "aws:cloudformation:logical-id": "ServerlessRestApi",
            "aws:cloudformation:stack-id": "arn:aws:cloudformation:eu-west-1:000011112222S:stack/FoodLeaStack/0cffbdd0-9636-11ec-be95-062821a5a16f",
            "aws:cloudformation:stack-name": "FoodLeaStack"
        },
        "disableExecuteApiEndpoint": false
    },
    {
        "id": "rkmadwkbe4",
        "name": "FoodLeaAPIFunction-API",
        "description": "Created by AWS Lambda",
        "createdDate": "2021-11-23T22:09:15+05:00",
        "apiKeySource": "HEADER",
        "endpointConfiguration": {
            "types": [
                "REGIONAL"
            ]
        },
        "disableExecuteApiEndpoint": false
    }
];

const getStages = [
    {
        "item": [
            {
                "deploymentId": "7wo1i4",
                "stageName": "Prod",
                "cacheClusterEnabled": true,
                "cacheClusterSize": "0.5",
                "cacheClusterStatus": "AVAILABLE",
                "methodSettings": {
                    "*/*": {
                        "metricsEnabled": false,
                        "dataTraceEnabled": false,
                        "throttlingBurstLimit": 5000,
                        "throttlingRateLimit": 10000.0,
                        "cachingEnabled": true,
                        "cacheTtlInSeconds": 0,
                        "cacheDataEncrypted": true,
                        "requireAuthorizationForCacheControl": true,
                        "unauthorizedCacheControlHeaderStrategy": "SUCCEED_WITH_RESPONSE_HEADER"
                    }
                },
                "tracingEnabled": false,
                "tags": {
                    "AWSServerlessAppNETCore": "true",
                    "aws:cloudformation:logical-id": "ServerlessRestApiProdStage",
                    "aws:cloudformation:stack-id": "arn:aws:cloudformation:eu-west-1:000011112222S:stack/FoodLeaStack/0cffbdd0-9636-11ec-be95-062821a5a16f",
                    "aws:cloudformation:stack-name": "FoodLeaStack"
                },
                "createdDate": "2022-02-25T17:26:32+05:00",
                "lastUpdatedDate": "2022-03-08T13:27:14+05:00"
            },
        ]
    },
    {
        "item": [
            {
                "deploymentId": "7wo1i4",
                "stageName": "Prod",
                "cacheClusterEnabled": false,
                "cacheClusterSize": "0.5",
                "cacheClusterStatus": "AVAILABLE",
                "methodSettings": {
                    "*/*": {
                        "metricsEnabled": false,
                        "dataTraceEnabled": false,
                        "throttlingBurstLimit": 5000,
                        "throttlingRateLimit": 10000.0,
                        "cachingEnabled": true,
                        "cacheTtlInSeconds": 0,
                        "cacheDataEncrypted": false,
                        "requireAuthorizationForCacheControl": true,
                        "unauthorizedCacheControlHeaderStrategy": "SUCCEED_WITH_RESPONSE_HEADER"
                    }
                },
                "tracingEnabled": false,
                "tags": {
                    "AWSServerlessAppNETCore": "true",
                    "aws:cloudformation:logical-id": "ServerlessRestApiProdStage",
                    "aws:cloudformation:stack-id": "arn:aws:cloudformation:eu-west-1:000011112222S:stack/FoodLeaStack/0cffbdd0-9636-11ec-be95-062821a5a16f",
                    "aws:cloudformation:stack-name": "FoodLeaStack"
                },
                "createdDate": "2022-02-25T17:26:32+05:00",
                "lastUpdatedDate": "2022-03-08T13:27:14+05:00"
            },
        ]
    },
    
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

describe('apigatewayResponseCaching', function () {
    describe('run', function () {
        it('should PASS if Response caching is enabled for API Gateway API stage', function (done) {
            const cache = createCache([getRestApis[0]], getStages[0]);
            apigatewayResponseCaching.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Response caching is enabled for API Gateway API stage')
                done();
            });
        });

        it('should FAIL if Response caching is not enabled for API Gateway API stage', function (done) {
            const cache = createCache([getRestApis[1]], getStages[1]);
            apigatewayResponseCaching.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Response caching is not enabled for API Gateway API stage')
                done();
            });
        });

        it('should PASS if No API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayResponseCaching.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No API Gateway rest APIs found')
                done();
            });
        });

        it('should PASS if No API Gateway Rest API Stages found', function (done) {
            const cache = createCache([getRestApis[0]], {item: []});
            apigatewayResponseCaching.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No rest API Stages found')
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest APIs', function (done) {
            const cache = createErrorCache();
            apigatewayResponseCaching.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for API Gateway rest APIs')
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest API Stages', function (done) {
            const cache = createCache([getRestApis[0]], null);
            apigatewayResponseCaching.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for API Gateway rest API Stages')
                done();
            });
        });

        it('should not return anything if get Rest APIs response is not found', function (done) {
            const cache = createNullCache();
            apigatewayResponseCaching.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});