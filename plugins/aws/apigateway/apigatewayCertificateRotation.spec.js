var expect = require('chai').expect;
var apigatewayCertificateRotation = require('./apigatewayCertificateRotation');

var cerExpiryFail = new Date();
cerExpiryFail.setMonth(cerExpiryFail.getMonth() + 1);

var cerExpiryPass = new Date();
cerExpiryPass.setMonth(cerExpiryPass.getMonth() + 1);

var cerExpired = new Date();
cerExpired.setMonth(cerExpired.getMonth() - 1);

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
    }
];

const getStages = [
    {
        "item": [
            {
                "deploymentId": "se8o93",
                "stageName": "dev",
                "clientCertificateId": "1bawn2",
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

const clientCertificate = [
    {
        "clientCertificateId": "1bawn2",
        "pemEncodedCertificate": "-----BEGIN CERTIFICATE-----\r\nMIIC6TCCAdGgAwIBAgIJAOyAuaO+1d1OMA0GCSqGSIb3DQEBCwUAMDQxCzAJBgNV\r\nBAYTAlVTMRAwDgYDVQQHEwdTZWF0dGxlMRMwEQYDVQQDEwpBcGlHYXRld2F5MB4X\r\nDTIwMTIxMTIxMzU0M1oXDTIxMTIxMTIxMzU0M1owNDELMAkGA1UEBhMCVVMxEDAO\r\nBgNVBAcTB1NlYXR0bGUxEzARBgNVBAMTCkFwaUdhdGV3YXkwggEiMA0GCSqGSIb3\r\nDQEBAQUAA4IBDwAwggEKAoIBAQCB3FraOYqorcdIebM66HTgPwbO5BVWDdmqxZfC\r\n1r2vjZq7LPHn+EuPgVh/BMnV2HAk4PiksXGJls3OZpoIArUHbuuO18cWEACkmvBv\r\n6fhB5D4reV75gBTFx12P4bwGl8E8tkq+o2SqnjqqHHdFHg4UhWQglBpWINS01MIh\r\n84DuzMhpvLfCqM1sW5+klGScMu5L9WvrHjtgKlIzvJkU5EWjkVgELhakF8GOKPun\r\nPD0RnbeVC0KaaPP1SpcwnCSj6h2EZhZYmS1Q9hO9tBnNuenzYhXsnK4HtkyVcL0/\r\nwO9xDP/H2hzTD2pEqKj+35B+aSu6fWdYLrsGMGlzN1Wtk1o3AgMBAAEwDQYJKoZI\r\nhvcNAQELBQADggEBAGKjj5qiad9S7H8FYILOhY/6fb3LRvo9lY3pR0D4MVG4nPdT\r\nkLJkBbFj7qqg9UqBqcZp3m7XHKm6+DdISkv/zfgutEikrlLD5lnYMsHljRKLwRFS\r\nZgOM7SnPX2dxRwNUSwBCjZIojf2+H8ENAcdpvHG3G/nwA/fWyoHY+UQfF29BkTtF\r\n9H5n3DjCQz3tm5njh+T1dVyVTuzXx3OdZulFrVi1sLmE81ca7ckdCZDs4DHMGwA9\r\nf3yPvk3B+DulD5YUnVSFDX84AK8f2xRc/5OUM5J+1DjD7bLKzikVzv+E+87ygEJb\r\nlNmz7yXJSkCzQ8jKCAva+Gw/lwC+K3AUCVFpxuU=\r\n-----END CERTIFICATE-----",
        "createdDate": "2020-12-12T02:35:43+05:00",
        "expirationDate": cerExpiryPass,
        "tags": {
            "cert": "cert"
        }
    },
    {
        "clientCertificateId": "1bawn2",
        "pemEncodedCertificate": "-----BEGIN CERTIFICATE-----\r\nMIIC6TCCAdGgAwIBAgIJAOyAuaO+1d1OMA0GCSqGSIb3DQEBCwUAMDQxCzAJBgNV\r\nBAYTAlVTMRAwDgYDVQQHEwdTZWF0dGxlMRMwEQYDVQQDEwpBcGlHYXRld2F5MB4X\r\nDTIwMTIxMTIxMzU0M1oXDTIxMTIxMTIxMzU0M1owNDELMAkGA1UEBhMCVVMxEDAO\r\nBgNVBAcTB1NlYXR0bGUxEzARBgNVBAMTCkFwaUdhdGV3YXkwggEiMA0GCSqGSIb3\r\nDQEBAQUAA4IBDwAwggEKAoIBAQCB3FraOYqorcdIebM66HTgPwbO5BVWDdmqxZfC\r\n1r2vjZq7LPHn+EuPgVh/BMnV2HAk4PiksXGJls3OZpoIArUHbuuO18cWEACkmvBv\r\n6fhB5D4reV75gBTFx12P4bwGl8E8tkq+o2SqnjqqHHdFHg4UhWQglBpWINS01MIh\r\n84DuzMhpvLfCqM1sW5+klGScMu5L9WvrHjtgKlIzvJkU5EWjkVgELhakF8GOKPun\r\nPD0RnbeVC0KaaPP1SpcwnCSj6h2EZhZYmS1Q9hO9tBnNuenzYhXsnK4HtkyVcL0/\r\nwO9xDP/H2hzTD2pEqKj+35B+aSu6fWdYLrsGMGlzN1Wtk1o3AgMBAAEwDQYJKoZI\r\nhvcNAQELBQADggEBAGKjj5qiad9S7H8FYILOhY/6fb3LRvo9lY3pR0D4MVG4nPdT\r\nkLJkBbFj7qqg9UqBqcZp3m7XHKm6+DdISkv/zfgutEikrlLD5lnYMsHljRKLwRFS\r\nZgOM7SnPX2dxRwNUSwBCjZIojf2+H8ENAcdpvHG3G/nwA/fWyoHY+UQfF29BkTtF\r\n9H5n3DjCQz3tm5njh+T1dVyVTuzXx3OdZulFrVi1sLmE81ca7ckdCZDs4DHMGwA9\r\nf3yPvk3B+DulD5YUnVSFDX84AK8f2xRc/5OUM5J+1DjD7bLKzikVzv+E+87ygEJb\r\nlNmz7yXJSkCzQ8jKCAva+Gw/lwC+K3AUCVFpxuU=\r\n-----END CERTIFICATE-----",
        "createdDate": "2020-12-12T02:35:43+05:00",
        "expirationDate": cerExpiryFail,
        "tags": {
            "cert": "cert"
        }
    },
    {
        "clientCertificateId": "1bawn2",
        "pemEncodedCertificate": "-----BEGIN CERTIFICATE-----\r\nMIIC6TCCAdGgAwIBAgIJAOyAuaO+1d1OMA0GCSqGSIb3DQEBCwUAMDQxCzAJBgNV\r\nBAYTAlVTMRAwDgYDVQQHEwdTZWF0dGxlMRMwEQYDVQQDEwpBcGlHYXRld2F5MB4X\r\nDTIwMTIxMTIxMzU0M1oXDTIxMTIxMTIxMzU0M1owNDELMAkGA1UEBhMCVVMxEDAO\r\nBgNVBAcTB1NlYXR0bGUxEzARBgNVBAMTCkFwaUdhdGV3YXkwggEiMA0GCSqGSIb3\r\nDQEBAQUAA4IBDwAwggEKAoIBAQCB3FraOYqorcdIebM66HTgPwbO5BVWDdmqxZfC\r\n1r2vjZq7LPHn+EuPgVh/BMnV2HAk4PiksXGJls3OZpoIArUHbuuO18cWEACkmvBv\r\n6fhB5D4reV75gBTFx12P4bwGl8E8tkq+o2SqnjqqHHdFHg4UhWQglBpWINS01MIh\r\n84DuzMhpvLfCqM1sW5+klGScMu5L9WvrHjtgKlIzvJkU5EWjkVgELhakF8GOKPun\r\nPD0RnbeVC0KaaPP1SpcwnCSj6h2EZhZYmS1Q9hO9tBnNuenzYhXsnK4HtkyVcL0/\r\nwO9xDP/H2hzTD2pEqKj+35B+aSu6fWdYLrsGMGlzN1Wtk1o3AgMBAAEwDQYJKoZI\r\nhvcNAQELBQADggEBAGKjj5qiad9S7H8FYILOhY/6fb3LRvo9lY3pR0D4MVG4nPdT\r\nkLJkBbFj7qqg9UqBqcZp3m7XHKm6+DdISkv/zfgutEikrlLD5lnYMsHljRKLwRFS\r\nZgOM7SnPX2dxRwNUSwBCjZIojf2+H8ENAcdpvHG3G/nwA/fWyoHY+UQfF29BkTtF\r\n9H5n3DjCQz3tm5njh+T1dVyVTuzXx3OdZulFrVi1sLmE81ca7ckdCZDs4DHMGwA9\r\nf3yPvk3B+DulD5YUnVSFDX84AK8f2xRc/5OUM5J+1DjD7bLKzikVzv+E+87ygEJb\r\nlNmz7yXJSkCzQ8jKCAva+Gw/lwC+K3AUCVFpxuU=\r\n-----END CERTIFICATE-----",
        "createdDate": "2020-12-12T02:35:43+05:00",
        "expirationDate": cerExpired,
        "tags": {
            "cert": "cert"
        }
    }
];

const createCache = (apis, stages, cert) => {
    var restApiId = (apis && apis.length && apis[0].id) ? apis[0].id : null;
    var clientCertificateId = (stages && stages.item && stages.item.length && stages.item[0].clientCertificateId) ? stages.item[0].clientCertificateId : null;

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
            getClientCertificate: {
                'us-east-1': {
                    [clientCertificateId]: {
                        data: cert
                    }
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
                        message: 'error fetching API Gateway Rest APIs'
                    },
                },
            },
            getStages: {
                'us-east-1': {
                    err: {
                        message: 'error fetching API Gateway Rest API Stages'
                    },
                },
            },
            getClientCertificate: {
                'us-east-1': {
                    err: {
                        message: 'error getting API Gateway Rest API Stage client certificate'
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
            },
            getClientCertificate: {
                'us-east-1': null
            }
        }
    };
};

describe('apigatewayCertificateRotation', function () {
    describe('run', function () {
        it('should PASS if API Gateway API stages do not need client certificate rotation', function (done) {
            const cache = createCache([getRestApis[0]], getStages[0], clientCertificate[0]);
            apigatewayCertificateRotation.run(cache, { api_certificate_rotation_limit: '20' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if API Gateway API stage needs client certificate rotation', function (done) {
            const cache = createCache([getRestApis[0]], getStages[0], clientCertificate[1]);
            apigatewayCertificateRotation.run(cache, { api_certificate_rotation_limit: '40' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if API Gateway API stage client certificate has already expired', function (done) {
            const cache = createCache([getRestApis[0]], getStages[0], clientCertificate[2]);
            apigatewayCertificateRotation.run(cache, { api_certificate_rotation_limit: '40' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No API Gateway Rest APIs found', function (done) {
            const cache = createCache([]);
            apigatewayCertificateRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if No API Gateway Rest API stages found', function (done) {
            const cache = createCache([getRestApis[0]], {item:[]});
            apigatewayCertificateRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if No API Gateway Rest API stage client certificate found', function (done) {
            const cache = createCache([getRestApis[0]], getStages[0], {});
            apigatewayCertificateRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest APIs', function (done) {
            const cache = createErrorCache();
            apigatewayCertificateRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get API Gateway Rest API stages', function (done) {
            const cache = createCache([getRestApis[0]], null);
            apigatewayCertificateRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get Rest APIs response is not found', function (done) {
            const cache = createNullCache();
            apigatewayCertificateRotation.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});