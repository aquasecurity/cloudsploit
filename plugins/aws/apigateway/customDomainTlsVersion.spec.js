var expect = require('chai').expect;
var apigatewayCustomDomainDeprecatedProtocol = require('./customDomainTlsVersion');

const getDomainNames = [
    {
            "domainName": "www.customDomain.com",
            "certificateUploadDate": "2022-11-10T15:24:06+05:00",
            "regionalDomainName": "d-kblr8fvsx5.execute-api.us-east-1.amazonaws.com",
            "regionalHostedZoneId": "Z1UJRXOUMOOFQ8",
            "regionalCertificateArn": "arn:aws:acm:us-east-1:1223334444:certificate/000f-1111g-8888t",
            "endpointConfiguration": {
                "types": [
                    "REGIONAL"
                ]
            },
            "domainNameStatus": "AVAILABLE",
            "securityPolicy": "TLS_1"
    },
    {
        "domainName": "www.customDomain.com",
        "certificateUploadDate": "2022-11-10T15:24:06+05:00",
        "regionalDomainName": "d-kblr8fvsx5.execute-api.us-east-1.amazonaws.com",
        "regionalHostedZoneId": "Z1UJRXOUMOOFQ8",
        "regionalCertificateArn": "arn:aws:acm:us-east-1:1223334444:certificate/000f-1111g-8888t",
        "endpointConfiguration": {
            "types": [
                "REGIONAL"
            ]
        },
        "domainNameStatus": "AVAILABLE",
        "securityPolicy": "TLS_1_2"
    }
];

const createCache = (domains) => {
    return {
        apigateway: {
            getDomainNames: {
                'us-east-1': {
                    data: domains
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        apigateway: {
            getDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error getting API Gateway Custom Domains'
                    },
                },
            },
        },
    };
};

describe('apigatewayCustomDomainDeprecatedProtocol', function () {
    describe('run', function () {
        it('should PASS if No API Gateway Custom Domains found', function (done) {
            const cache = createCache([]);
            apigatewayCustomDomainDeprecatedProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('No API Gateway Custom Domains found');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should PASS if API Gateway Custom Domain is using current minimum TLS version', function (done) {
            const cache = createCache([getDomainNames[1]]);
            apigatewayCustomDomainDeprecatedProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('is using current minimum TLS version');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if API Gateway Custom Domain is using deprecated TLS version', function (done) {
            const cache = createCache([getDomainNames[0]]);
            apigatewayCustomDomainDeprecatedProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('is using deprecated TLS version');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to query for API Gateways', function (done) {
            const cache = createErrorCache();
            apigatewayCustomDomainDeprecatedProtocol.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.include('Unable to query for API Gateway Custom Domain');
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
})