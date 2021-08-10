var assert = require('assert');
var expect = require('chai').expect;
var esCmkEncryptionEnabled = require('./esCmkEncryptionEnabled');

const domains =  [
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: true,
                KmsKeyId: '(Default) aws/es'
            }
        }
    },
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: true,
                KmsKeyId: 'alias/aws/es'
            }
        }
    },
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: false
            }
        }
    },
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: true
            }
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

describe('esCmkEncryptionEnabled', function () {
    describe('run', function () {
        
        it('should PASS if CMK based ES encryption is enabled', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            esCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no ES domains present', function (done) {
            const cache = createCache([], {});
            esCmkEncryptionEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ES encryption config is disabled', function (done) {
            const cache = createCache([domainNames[0]], domains[2]);
            esCmkEncryptionEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if ES encryption config does not have kms key id', function (done) {
            const cache = createCache([domainNames[0]], domains[3]);
            esCmkEncryptionEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if default ES encryption is enabled', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            esCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            esCmkEncryptionEnabled.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    })
})