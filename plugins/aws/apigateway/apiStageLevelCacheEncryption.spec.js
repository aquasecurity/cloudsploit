var expect = require('chai').expect;
var apiStageLevelCacheEncryption = require('./apiStageLevelCacheEncryption');

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
            "aws:cloudformation:stack-id": "arn:aws:cloudformation:eu-west-1:232489870748:stack/FoodLeaStack/0cffbdd0-9636-11ec-be95-062821a5a16f",
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
                    "aws:cloudformation:stack-id": "arn:aws:cloudformation:eu-west-1:232489870748:stack/FoodLeaStack/0cffbdd0-9636-11ec-be95-062821a5a16f",
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
                        "cacheDataEncrypted": false,
                        "requireAuthorizationForCacheControl": true,
                        "unauthorizedCacheControlHeaderStrategy": "SUCCEED_WITH_RESPONSE_HEADER"
                    }
                },
                "tracingEnabled": false,
                "tags": {
                    "AWSServerlessAppNETCore": "true",
                    "aws:cloudformation:logical-id": "ServerlessRestApiProdStage",
                    "aws:cloudformation:stack-id": "arn:aws:cloudformation:eu-west-1:232489870748:stack/FoodLeaStack/0cffbdd0-9636-11ec-be95-062821a5a16f",
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
                "deploymentId": "8ev3a3",
                "stageName": "Stage",
                "cacheClusterEnabled": false,
                "cacheClusterStatus": "NOT_AVAILABLE",
                "methodSettings": {},
                "tracingEnabled": false,
                "createdDate": "2022-02-25T17:26:28+05:00",
                "lastUpdatedDate": "2022-02-25T17:26:28+05:00"
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

describe('apiStageLevelCacheEncryption', function () {
    describe('run', function () {
        it('should PASS if API Gateway stage encrypts cache data', function (done) {
            const cache = createCache([getRestApis[0]], getStages[0]);
            apiStageLevelCacheEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('API Gateway stage encrypts cache data')
                done();
            });
        });

        it('should FAIL if API Gateway stage does not encrypt cache data', function (done) {
            const cache = createCache([getRestApis[1]], getStages[1]);
            apiStageLevelCacheEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('API Gateway stage does not encrypt cache data')
                done();
            });
        });

        it('should PASS if Response caching is not enabled for the API stage', function (done) {
            const cache = createCache([getRestApis[0]], getStages[2]);
            apiStageLevelCacheEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Response caching is not enabled for the API stage')
                done();
            });
        });

        it('should PASS if No API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apiStageLevelCacheEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No API Gateway rest APIs found')
                done();
            });
        });

        it('should PASS if No API Gateway Rest API Stages found', function (done) {
            const cache = createCache([getRestApis[0]], {item: []});
            apiStageLevelCacheEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No rest API Gateway stages found')
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest APIs', function (done) {
            const cache = createErrorCache();
            apiStageLevelCacheEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for API Gateway rest APIs')
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Stages', function (done) {
            const cache = createCache([getRestApis[0]], null);
            apiStageLevelCacheEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query API Gateway stages')
                done();
            });
        });
    });
});