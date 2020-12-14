var expect = require('chai').expect;
var cloudWatchEncryptedLogs = require('./cloudWatchEncryptedLogs');

const getSecurityConfigurations = [
    {
        "Name": "glue-test-config",
        "CreatedTimeStamp": "2020-12-15T01:18:18.391000+05:00",
        "EncryptionConfiguration": {
            "S3Encryption": [
                {
                    "S3EncryptionMode": "DISABLED"
                }
            ],
            "CloudWatchEncryption": {
                "CloudWatchEncryptionMode": "SSE-KMS",
                "KmsKeyArn": "arn:aws:kms:us-east-1:111122223333:key/e400fb3c-7bb5-4e7e-8ecc-250982820000"
            },
            "JobBookmarksEncryption": {
                "JobBookmarksEncryptionMode": "DISABLED"
            }
        }
    },
    {
        "Name": "config-test2",
        "CreatedTimeStamp": "2020-12-15T02:20:28.329000+05:00",
        "EncryptionConfiguration": {
            "S3Encryption": [
                {
                    "S3EncryptionMode": "DISABLED"
                }
            ],
            "CloudWatchEncryption": {
                "CloudWatchEncryptionMode": "DISABLED"
            },
            "JobBookmarksEncryption": {
                "JobBookmarksEncryptionMode": "DISABLED"
            }
        }
    }
];

const createCache = (configurations) => {
    return {
        glue: {
            getSecurityConfigurations: {
                'us-east-1': {
                    data: configurations
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        glue: {
            getSecurityConfigurations: {
                'us-east-1': {
                    err: {
                        message: 'error getting AWS Glue security configurations'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        glue: {
            getSecurityConfigurations: {
                'us-east-1': null
            }
        },
    };
};

describe('cloudWatchEncryptedLogs', function () {
    describe('run', function () {
        it('should PASS if AWS Glue security configuration has CloudWatch logs encryption enabled', function (done) {
            const cache = createCache([getSecurityConfigurations[0]]);
            cloudWatchEncryptedLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AWS Glue security configuration has CloudWatch logs encryption disabled', function (done) {
            const cache = createCache([getSecurityConfigurations[1]]);
            cloudWatchEncryptedLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No AWS Glue security configurations found', function (done) {
            const cache = createCache([]);
            cloudWatchEncryptedLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to get AWS Glue security configurations', function (done) {
            const cache = createErrorCache();
            cloudWatchEncryptedLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get security configurations response is not found', function (done) {
            const cache = createNullCache();
            cloudWatchEncryptedLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
}); 