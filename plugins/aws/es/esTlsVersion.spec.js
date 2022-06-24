var expect = require('chai').expect;
var esTlsVersion = require('./esTlsVersion');

const domainNames = [
    {
        "DomainName": "test-domain"
    }
];

const domains = [
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain",
            "DomainName": "test-domain",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain",
            "DomainEndpointOptions": {
                "EnforceHTTPS": true,
                "TLSSecurityPolicy": 'Policy-Min-TLS-1-2-2019-07',
                "CustomEndpointEnabled": false,
                "CustomEndpoint": null,
            }
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain",
            "DomainName": "test-domain",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain",
            "DomainEndpointOptions": {
                "EnforceHTTPS": true,
                "TLSSecurityPolicy": 'Policy-Min-TLS-1-0-2019-07',
                "CustomEndpointEnabled": false,
                "CustomEndpoint": null,
            }
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain",
            "DomainName": "test-domain",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain",
            "DomainEndpointOptions": {
                "EnforceHTTPS": true,
                "CustomEndpointEnabled": false,
                "CustomEndpoint": null,
            }
        }
    }
];

const createCache = (domainNames, domains) => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: null,
                    data: domainNames
                }
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    'test-domain': {
                        err: null,
                        data: domains
                    }
                }
            }
        }
    }
};

const createErrorCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': null,
            },
        },
    };
};

describe('esTlsVersion', function () {
    describe('run', function () {
        it('should PASS if ES domains have TLS version 1.2', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ES domains do not have TLS version 1.2', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            esTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if ES domain does not have TLSSecurityPolicy property', function (done) {
            const cache = createCache([domainNames[0]], domains[2]);
            esTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no domain names found', function (done) {
            const cache = createCache([], {});
            esTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error listing domain names', function (done) {
            const cache = createErrorCache();
            esTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for domain names', function (done) {
            const cache = createNullCache();
            esTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
