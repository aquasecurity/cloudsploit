var expect = require('chai').expect;
var osDedicatedMasterEnabled = require('./opensearchDedicatedMasterEnabled');

const domains =  [
    {
        "DomainStatus": {
            "DomainName": 'mydomain',
            "ARN": 'arn:1234',
            "ClusterConfig": {
                "DedicatedMasterEnabled": true
            }
        }
    },
    {
        "DomainStatus": {
            "DomainName": 'mydomain',
            "ARN": '"arn":1234',
            "ClusterConfig": {
                "DedicatedMasterEnabled": false
            }
        }
    },
    {
        "DomainStatus": {
            "DomainName": 'mydomain',
            "ARN": 'arn:1234',
            "ClusterConfig": {}
        }
    }
]

const domainNames = [
    {
        DomainName: 'mydomain'
    }
]

const createCache = (listData, descData) => {
    return {
        opensearch: {
            listDomainNames: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeDomain: {
                'us-east-1': {
                    'mydomain': {
                        err: null,
                        data: descData
                    }
                }
            }
        }
    }
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
            describeDomain: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        opensearch: {
            listDomainNames: {
                'us-east-1': null,
            },
            describeDomain: {
                'us-east-1': null
            }
        },
    };
}

describe('osDedicatedMasterEnabled', function () {
    describe('run', function () {        
        it('should PASS if dedicated master nodes are used', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            osDedicatedMasterEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OpenSearch domain is configured to use dedicated master node')
                done();
            });
        });

        it('should PASS if no opensearch domains present', function (done) {
            const cache = createCache([], {});
            osDedicatedMasterEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OpenSearch domains found')
                done();
            });
        });

        it('should FAIL if dedicated master node not used', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            osDedicatedMasterEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenSearch domain is not configured to use dedicated master node')
                done();
            });
        });

        it('should FAIL if opensearch cluster config does not have dedicated master enabled key', function (done) {
            const cache = createCache([domainNames[0]], domains[2]);
            osDedicatedMasterEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenSearch domain is not configured to use dedicated master node')
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            osDedicatedMasterEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for OpenSearch domains')
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            osDedicatedMasterEnabled.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    })
});
