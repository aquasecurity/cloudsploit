var expect = require('chai').expect;
var apigatewayRequestValidation = require('./apigatewayRequestValidation');

const createCache = (getRestApisData, getRequestValidatorsData) => {
    if (getRestApisData && getRestApisData.length && getRestApisData[0].id) var restApiId = getRestApisData[0].id;
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': {
                    data: getRestApisData
                }
            },
            getRequestValidators: {
                'us-east-1': {
                    [restApiId]: {
                        data: {
                            items: getRequestValidatorsData
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
            getRequestValidators: {
                'us-east-1': {
                    err: {
                        message: 'error fetching API Gateway Request Validators'
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
            getRequestValidators: {
                'us-east-1': null
            }
        }
    };
};

describe('apigatewayRequestValidation', function () {
    describe('run', function () {
        it('should return UNKNOWN if unable to query for API Gateway Rest APIs', function (done) {
            const cache = createErrorCache();
            apigatewayRequestValidation.run(cache, {} , (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('Unable to query for API Gateway Rest APIs:');
                done();
            });
        });

        it('should return PASS if no API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayRequestValidation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No API Gateway Rest APIs found');
                done();
            });
        });

        it('should return FAIL if no request validators exist for API Gateway Rest API', function (done) {
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
            const getRequestValidatorsData = [];
            const cache = createCache(getRestApisData, getRequestValidatorsData);
            apigatewayRequestValidation.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect (results[0].message).to.include('No request validators found for API Gateway Rest API');
                done();
            });
        });

        it('should return PASS if validators exist for API Gateway Rest API', function (done) {
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
            const getRequestValidatorsData = [
                [
                    {
                      id: "70wn19",
                      name: "Validate body",
                      validateRequestBody: true,
                      validateRequestParameters: false,
                    },
                    {
                      id: "z06eap",
                      name: "Validate query string parameters and headers",
                      validateRequestBody: false,
                      validateRequestParameters: true,
                    },
                  ]
            ];
            const cache = createCache(getRestApisData, getRequestValidatorsData);
            apigatewayRequestValidation.run(cache,{}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Request validators found for API Gateway Rest API')
                done();
            });
        });
         it('should not return anything if get Rest APIs response is not found', function (done) {
            const cache = createNullCache();
            apigatewayRequestValidation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
