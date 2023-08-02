const expect = require('chai').expect;
const esZoneAwarenessEnabled = require('./esZoneAwarenessEnabled');

const domainNames = [
    {
        "DomainName": "test-domain3-1"
    },
    {
        "DomainName": "test-domain-2"
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
            "ElasticsearchClusterConfig": {
                "ZoneAwarenessEnabled": false
            },
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
            "ElasticsearchClusterConfig": {
                "ZoneAwarenessEnabled": true
            },
            "AccessPolicies": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:us-east-1:560213429563:domain/es-domain-1/*\"}]}",
        }
    },
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



describe('esZoneAwarenessEnabled', function () {
    describe('run', function () {
        it('should FAIL if domain zone awareness is not enabled', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esZoneAwarenessEnabled.run(cache, {},(err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Zone Awareness is not enabled for ES domain');
                done();
            });
        });

        it('should PASS if domain zone awareness is enabled', function (done) {
            const cache = createCache([domainNames[1]], domains[1]);
            esZoneAwarenessEnabled.run(cache, {},(err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Zone Awareness is enabled for ES domain');
                done();
            });
        });

        it('should PASS if no domain names found', function (done) {
            const cache = createCache([]);
            esZoneAwarenessEnabled.run(cache, {},(err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No ES domains found');
                done();
            });
        });

        it('should UNKNOWN if unable to list domain', function (done) {
            const cache = createErrorCache();
            esZoneAwarenessEnabled.run(cache, {},(err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for ES domains:');
                done();
            });
        });

        it('should not return unknown results if unable to describe domain names', function (done) {
            const cache = createCache([domainNames[0]],null);
            esZoneAwarenessEnabled.run(cache, {},(err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for ES domain config');
                done();
            });
        });
    });
});
