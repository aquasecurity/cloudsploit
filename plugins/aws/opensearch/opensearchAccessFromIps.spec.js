const expect = require('chai').expect;
const osAccessFromIps = require('./opensearchAccessFromIps');

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
        opensearch: {
            listDomainNames: {
                'us-east-1': {
                    data: domainNames,
                },
            },
            describeDomain: {
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
        opensearch: {
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

describe('osAccessFromIps', function () {
    describe('run', function () {
        it('should FAIL if domain is publicly exposed', function (done) {
            const cache = createCache([domainNames[1]], domains[1]);
            osAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.includes('OpenSearch domain "test-domain-2" is publicly exposed');
                done();
            });
        });

        it('should PASS if domain is not exposed to any unknown IP addresses', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            osAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13,52.95.245.0/24' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.includes('OpenSearch domain "test-domain3-1" is not accessible from any unknown IP address');
                done();
            });
        });

        it('should FAIL if domain is not exposed to unknown IP addresses', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            osAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/16' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.includes('OpenSearch domain "test-domain3-1" is accessible from these unknown IP addresses: 18.208.0.0/13, 52.95.245.0/24');
                done();
            });
        });

        it('should PASS if no access policy found', function (done) {
            const cache = createCache([domainNames[2]], domains[2]);
            osAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.includes('No access policy found');
                done();
            });
        });

        it('should PASS if no domain names found', function (done) {
            const cache = createCache([]);
            osAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.includes('No OpenSearch domains found')
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            osAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.includes('Unable to query for OpenSearch domains')
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            osAccessFromIps.run(cache, { whitelisted_ip_addresses: '18.208.0.0/13' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return any results if whitelisted IP addresses are not provided in settings', function (done) {
            const cache = createNullCache();
            osAccessFromIps.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
