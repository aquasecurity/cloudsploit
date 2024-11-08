var expect = require('chai').expect;
var apigatewayV2AccessLogging = require('./apigatewayV2AccessLogging');

const createCache = (getApis, getStages) => {
    if (getApis && getApis.length && getApis[0].ApiId) var restApiId = getApis[0].ApiId;
    return {
        apigatewayv2: {
            getApis: {
                'us-east-1': {
                    data: getApis
                }
            },
            getStages: {
                'us-east-1': {
                    [restApiId]: {
                        data: {
                            Items: getStages
                        }
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        apigatewayv2: {
            getApis: {
                'us-east-1': {
                    err: {
                        message: 'error fetching API Gateway v2 APIs'
                    },
                },
            },
            getStages: {
                'us-east-1': {
                    err: {
                        message: 'error fetching API Gateway v2 stages'
                    },
                },
            }
           
        },
    };
};

const createUnknownForStage = (api) => {
    return {
        apigatewayv2: {
            getApis: {
                'us-east-1': {
                    data: api
                }
            },
            getStages: {
                'us-east-1': 'err'
            }
        }
    };
};

describe('apigatewayV2AccessLogging', function () {
    describe('run', function () {
        it('should return UNKNOWN if unable to query for API Gateway v2 APIs', function (done) {
            const cache = createErrorCache();
            apigatewayV2AccessLogging.run(cache, {} , (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('Unable to query for API Gateway V2 APIs:');
                done();
            });
        });

        it('should return PASS if no API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayV2AccessLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No API Gateway V2 APIs found');
                done();
            });
        });

        it('should return PASS if no stages found', function (done) {
            const getApis = [
                {
                    ApiId: 'api-id',
                    name: 'TestAPI',
                    description: 'Test API',
                    createdDate: 1621916018,
                    apiKeySource: 'HEADER',
                    endpointConfiguration: {
                        types: ['REGIONAL']
                    }
                }
            ];
            const getStages = [];
            const cache = createCache(getApis, getStages);
            apigatewayV2AccessLogging.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No API Gateway V2 API Stages found');
                done();
            });
        });

        it('should return PASS if Api gateway v2 stage has access logging enabled', function (done) {
            const getApis = [
                {
                    ApiId: 'api-id',
                    name: 'TestAPI',
                    description: 'Test API',
                    createdDate: 1621916018,
                    apiKeySource: 'HEADER',
                    endpointConfiguration: {
                        types: ['REGIONAL']
                    }
                }
            ];
            const getStages = [
                {
                    "AutoDeploy": true,
                    "CreatedDate": "2023-12-11T20:07:28.000Z",
                    "DefaultRouteSettings": {
                      "DetailedMetricsEnabled": false
                    },
                    "DeploymentId": "biw5qf",
                    "Description": "Created by AWS Lambda",
                    "LastDeploymentStatusMessage": "Successfully deployed stage with deployment ID 'biw5qf'",
                    "LastUpdatedDate": "2023-12-11T20:07:29.000Z",
                    "RouteSettings": {},
                    "StageName": "default",
                    "StageVariables": {},
                    "Tags": {},
                    "AccessLogSetting": {
                        "LogArn": "arn:aws:1234:log"
                    }
                  }
            ];
            const cache = createCache(getApis, getStages);
            apigatewayV2AccessLogging.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('API Gateway V2 API stage has access logging enabled')
                done();
            });
        });

        it('should return PASS if Api gateway v2 stage has access logging enabled', function (done) {
            const getApis = [
                {
                    ApiId: 'api-id',
                    name: 'TestAPI',
                    description: 'Test API',
                    createdDate: 1621916018,
                    apiKeySource: 'HEADER',
                    endpointConfiguration: {
                        types: ['REGIONAL']
                    }
                }
            ];
            const getStages = [
                {
                    "AutoDeploy": true,
                    "CreatedDate": "2023-12-11T20:07:28.000Z",
                    "DefaultRouteSettings": {
                      "DetailedMetricsEnabled": false
                    },
                    "DeploymentId": "biw5qf",
                    "Description": "Created by AWS Lambda",
                    "LastDeploymentStatusMessage": "Successfully deployed stage with deployment ID 'biw5qf'",
                    "LastUpdatedDate": "2023-12-11T20:07:29.000Z",
                    "RouteSettings": {},
                    "StageName": "default",
                    "StageVariables": {},
                    "Tags": {},
                  }
            ];
            const cache = createCache(getApis, getStages);
            apigatewayV2AccessLogging.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('API Gateway V2 API stage does not have access logging enabled')
                done();
            });
        });

        it('should return UNKNOWN if unable to query for api stages', function (done) {
            const getApis = [
                {
                    ApiId: 'api-id',
                    name: 'TestAPI',
                    description: 'Test API',
                    createdDate: 1621916018,
                    apiKeySource: 'HEADER',
                    endpointConfiguration: {
                        types: ['REGIONAL']
                    }
                }
            ];

            const cache = createUnknownForStage(getApis);
            apigatewayV2AccessLogging.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for API Gateway V2 API Stages:')
                done();
            });
        });
    });
});
