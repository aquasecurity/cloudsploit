const expect = require('chai').expect;
const opensearchEnableAuditLogs = require('./opensearchEnableAuditLogs');

const domainNames = [
    {
        "DomainName": "test-domain3-104"
    },
    {
        "DomainName": "test-domain-104"
    },
    {
        "DomainName": "test-domain2-104"
    }
];

const domains = [
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain-104",
            "DomainName": "test-domain-104",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain-104",
            "Created": true,
            "Deleted": false,
                    "LogPublishingOptions": {
                        "AUDIT_LOGS": { 
                            "Enabled": true 
                        }
                    }
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain3-104",
            "DomainName": "test-domain3-104",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain3-104",
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
        opensearch: {
            listDomainNames: {
                'us-east-1': null,
            },
        },
    };
};

describe('opensearchEnableAuditLogs', function () {
    describe('run', function () {
        it('should FAIL if Audit Logs feature is not enabled for OpenSearch domain', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            opensearchEnableAuditLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.include('us-east-1')
                done();
            });
        });

        it('should PASS if Audit Logs feature is enabled for OpenSearch domain', function (done) {
            const cache = createCache([domainNames[1]], domains[0]);
            opensearchEnableAuditLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.include('us-east-1')
                done();
            });
        });


        it('should PASS if no domain names found', function (done) {
            const cache = createCache([]);
            opensearchEnableAuditLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.include('us-east-1')
                done();
            });
        });

        it('should UNKNOWN if there was an error listing domain names', function (done) {
            const cache = createErrorCache();
            opensearchEnableAuditLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.include('us-east-1')
                done();
            });
        });

        it('should not return any results if unable to query for domain names', function (done) {
            const cache = createNullCache();
            opensearchEnableAuditLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
