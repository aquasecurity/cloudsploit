var expect = require('chai').expect;
var apigatewayV2Authorization = require('./apigatewayV2Authorization');

const createCache = (getApis, getAuthorizersData) => {
    if (getApis && getApis.length && getApis[0].ApiId) var restApiId = getApis[0].ApiId;
    return {
        apigatewayv2: {
            getApis: {
                'us-east-1': {
                    data: getApis
                }
            },
            getAuthorizers: {
                'us-east-1': {
                    [restApiId]: {
                        data: {
                            Items: getAuthorizersData
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
            getAuthorizers: {
                'us-east-1': {
                    err: {
                        message: 'error fetching API Gateway v2 Authorizers'
                    },
                },
            }
           
        },
    };
};

const createNullCache = () => {
    return {
        apigatewayv2: {
            getApis: {
                'us-east-1': null
            },
            getAuthorizers: {
                'us-east-1': null
            }
        }
    };
};

describe('apigatewayV2Authorization', function () {
    describe('run', function () {
        it('should return UNKNOWN if unable to query for API Gateway v2 APIs', function (done) {
            const cache = createErrorCache();
            apigatewayV2Authorization.run(cache, {} , (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('Unable to query for API Gateway V2 APIs:');
                done();
            });
        });

        it('should return PASS if no API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayV2Authorization.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No API Gateway V2 APIs found');
                done();
            });
        });

        it('should return FAIL if no authorizers exist for API Gateway Rest API', function (done) {
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
            const getAuthorizersData = [];
            const cache = createCache(getApis, getAuthorizersData);
            apigatewayV2Authorization.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No authorizers found for API Gateway V2 API');
                done();
            });
        });

        it('should return PASS if authorizers exist for API Gateway V2 API', function (done) {
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
            const cache = createCache(getApis, getAuthorizersData);
            apigatewayV2Authorization.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Authorizers found for API Gateway V2 API')
                done();
            });
        });
         it('should not return anything if get Rest APIs response is not found', function (done) {
            const cache = createNullCache();
            apigatewayV2Authorization.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
