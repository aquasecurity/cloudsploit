const expect = require('chai').expect;
const esAccessFromIps = require('./esAccessFromIps');

const domainNames = [
    {
        "DomainName": "test-domain3-1"
    },
    {
        "DomainName": "test-domain-2"
    },
    {
        "DomainName": "test-domain-3"
    }
];

const domains = [
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain-1",
            "DomainName": "test-domain-1",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain-1",
            "Created": true,
            "Deleted": false,
            "AccessPolicies": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:us-east-1:560213429563:domain/es-domain-1/*\",\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":[\"18.208.0.0/13\",\"52.95.245.0/24\"]}}}]}",
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain-2",
            "DomainName": "test-domain-2",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain-2",
            "Created": true,
            "Deleted": false,
            "AccessPolicies": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:us-east-1:560213429563:domain/es-domain-1/*\"}]}",
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain-3",
            "DomainName": "test-domain-2",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain-2",
            "Created": true,
            "Deleted": false,
        }
    }
];

const createCache = (domainNames, domains) => {
    if (domainNames && domainNames.length) var name = domainNames[0].DomainName;
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    data: domainNames,
                },
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    [name]: {
                        data: domains
                    }
                }
            }
        },
    };
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

describe('esAccessFromIps', function () {
    describe('run', function () {
        it('should FAIL if domain is publicy exposed', function (done) {
            const cache = createCache([domainNames[1]], domains[1]);
            esAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if domain is not exposed to any unknown IP addresses', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13,52.95.245.0/24' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if domain is not exposed to unknown IP addresses', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/16' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no access policy found', function (done) {
            const cache = createCache([domainNames[2]], domains[2]);
            esAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no domain names found', function (done) {
            const cache = createCache([]);
            esAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            esAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            esAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return any results if whitelisted IP addresses are not provided in settings', function (done) {
            const cache = createNullCache();
            esAccessFromIps.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
