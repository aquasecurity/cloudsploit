var expect = require('chai').expect;
var apigatewayTlsDefaultEndpoint = require('./apigatewayDefaultEndpointDisabled');

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
        },
        "disableExecuteApiEndpoint": false
    },
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
        },
        "disableExecuteApiEndpoint": true
    }
];

const createCache = (apis) => {
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': {
                    data: apis
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
        },
    };
};

describe('apigatewayTlsDefaultEndpoint', function () {
    describe('run', function () {
        it('should PASS if No API Gateway rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayTlsDefaultEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No API Gateway rest APIs found');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should PASS if API Gateway is not accessible through default endpoint', function (done) {
            const cache = createCache([getRestApis[1]]);
            apigatewayTlsDefaultEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('is not accessible through default endpoint');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if API Gateway is accessible through default endpoint', function (done) {
            const cache = createCache([getRestApis[0]]);
            apigatewayTlsDefaultEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('is accessible through default endpoint');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to query for API Gateways', function (done) {
            const cache = createErrorCache();
            apigatewayTlsDefaultEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for API Gateway rest APIs');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
})