var expect = require('chai').expect;
var esDedicatedMasterEnabled = require('./esDedicatedMasterEnabled');

const domains =  [
    {
        "DomainStatus": {
            "DomainName": 'mydomain',
            "ARN": 'arn:1234',
            "ElasticsearchClusterConfig": {
                "DedicatedMasterEnabled": true
            }
        }
    },
    {
        "DomainStatus": {
            "DomainName": 'mydomain',
            "ARN": '"arn":1234',
            "ElasticsearchClusterConfig": {
                "DedicatedMasterEnabled": false
            }
        }
    },
    {
        "DomainStatus": {
            "DomainName": 'mydomain',
            "ARN": 'arn:1234',
            "ElasticsearchClusterConfig": {}
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
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeElasticsearchDomain: {
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
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            },
            describeElasticsearchDomain: {
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
        es: {
            listDomainNames: {
                'us-east-1': null,
            },
            describeElasticsearchDomain: {
                'us-east-1': null
            }
        },
    };
}

describe('esDedicatedMasterEnabled', function () {
    describe('run', function () {        
        it('should PASS if dedicated master nodes are used', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esDedicatedMasterEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no ES domains present', function (done) {
            const cache = createCache([], {});
            esDedicatedMasterEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if dedicated master node not used', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            esDedicatedMasterEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if elastic search cluster config does not have dedicated master enabled key', function (done) {
            const cache = createCache([domainNames[0]], domains[2]);
            esDedicatedMasterEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            esDedicatedMasterEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            esDedicatedMasterEnabled.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    })
});
