var expect = require('chai').expect;
var apigatewayAuthorization = require('./apigatewayAuthorization');

const createCache = (getRestApisData, getAuthorizersData) => {
    if (getRestApisData && getRestApisData.length && getRestApisData[0].id) var restApiId = getRestApisData[0].id;
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': {
                    data: getRestApisData
                }
            },
            getAuthorizers: {
                'us-east-1': {
                    [restApiId]: {
                        data: {
                            items: getAuthorizersData
                        }
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': {
                    err: {
                        message: 'error fetching API Gateway Rest APIs'
                    },
                },
            },
            getAuthorizers: {
                'us-east-1': {
                    err: {
                        message: 'error fetching API Gateway Authorizers'
                    },
                },
            }
           
        },
    };
};

const createNullCache = () => {
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': null
            },
            getAuthorizers: {
                'us-east-1': null
            }
        }
    };
};

describe('apigatewayAuthorization', function () {
    describe('run', function () {
        it('should return UNKNOWN if unable to query for API Gateway Rest APIs', function (done) {
            const cache = createErrorCache();
            apigatewayAuthorization.run(cache, {} , (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('Unable to query for API Gateway Rest APIs:');
                done();
            });
        });

        it('should return PASS if no API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayAuthorization.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No API Gateway Rest APIs found');
                done();
            });
        });

        it('should return FAIL if no authorizers exist for API Gateway Rest API', function (done) {
            const getRestApisData = [
                {
                    id: 'api-id',
                    name: 'TestAPI',
                    description: 'Test API',
                    createdDate: 1621916018,
                    apiKeySource: 'HEADER',
                    endpointConfiguration: {
                        types: ['REGIONAL']
                    }
                }
            ];
            const getAuthorizersData = [];
            const cache = createCache(getRestApisData, getAuthorizersData);
            apigatewayAuthorization.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No authorizers found for API Gateway Rest API ');
                done();
            });
        });

        it('should return PASS if authorizers exist for API Gateway Rest API', function (done) {
            const getRestApisData = [
                {
                    id: 'api-id',
                    name: 'TestAPI',
                    description: 'Test API',
                    createdDate: 1621916018,
                    apiKeySource: 'HEADER',
                    endpointConfiguration: {
                        types: ['REGIONAL']
                    }
                }
            ];
            const getAuthorizersData = [
                {
                    name: 'authorizer1',
                    type: 'REQUEST',
                    authType: 'custom',
                    authorizerUri: 'arn:aws:lambda:us-east-1:123456789012:function:authorizer1',
                    identitySource: 'method.request.header.Authorization',
                    authorizerResultTtlInSeconds: 300
                },
                {
                    name: 'authorizer2',
                    type: 'REQUEST',
                    authType: 'custom',
                    authorizerUri: 'arn:aws:lambda:us-east-1:123456789012:function:authorizer2',
                    identitySource: 'method.request.header.Authorization',
                    authorizerResultTtlInSeconds: 300
                }
            ];
            const cache = createCache(getRestApisData, getAuthorizersData);
            apigatewayAuthorization.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Authorizers found for API Gateway Rest API ')
                done();
            });
        });
         it('should not return anything if get Rest APIs response is not found', function (done) {
            const cache = createNullCache();
            apigatewayAuthorization.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
