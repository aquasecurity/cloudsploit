var expect = require('chai').expect;
var apigatewayContentEncoding = require('./apigatewayContentEncoding');

const getRestApis = [
    {
        "id": "98mjrkp8ia",
        "name": "PetStore",
        "description": "Your first API with Amazon API Gateway. This is a sample API that integrates via HTTP with our demo Pet Store endpoints",
        "createdDate": 1604621029,
        "apiKeySource": "HEADER",
        "minimumCompressionSize": 1000,
        "endpointConfiguration": {
            "types": [
                "REGIONAL"
            ]
        }
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
        }
    }
];

const createCache = (apis) => {
    if (apis && apis.length && apis[0].id) var restApiId = apis[0].id;
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

const createNullCache = () => {
    return {
        apigateway: {
            getRestApis: {
                'us-east-1': null
            }
        },
    };
};

describe('apigatewayContentEncoding', function () {
    describe('run', function () {
        it('should PASS if API Gateway API stage has content encoding enabled', function (done) {
            const cache = createCache([getRestApis[0]]);
            apigatewayContentEncoding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if API Gateway API stage does not have content encoding enabled', function (done) {
            const cache = createCache([getRestApis[1]]);
            apigatewayContentEncoding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayContentEncoding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest APIs', function (done) {
            const cache = createErrorCache();
            apigatewayContentEncoding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get Rest APIs response is not found', function (done) {
            const cache = createNullCache();
            apigatewayContentEncoding.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});