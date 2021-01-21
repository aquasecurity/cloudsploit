var expect = require('chai').expect;
var bookmarkEncryptionEnabled = require('./bookmarkEncryptionEnabled');

const getSecurityConfigurations = [
    {
        "Name": "config-test",
        "CreatedTimeStamp": "2020-12-15T03:32:22.300000+05:00",
        "EncryptionConfiguration": {
            "S3Encryption": [
                {
                    "S3EncryptionMode": "SSE-KMS",
                    "KmsKeyArn": "arn:aws:kms:us-east-1:111122223333:key/7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec"
                }
            ],
            "CloudWatchEncryption": {
                "CloudWatchEncryptionMode": "DISABLED"
            },
            "JobBookmarksEncryption": {
                "JobBookmarksEncryptionMode": "CSE-KMS",
                "KmsKeyArn": "arn:aws:kms:us-east-1:111122223333:key/e400fb3c-7bb5-4e7e-8ecc-25098282573a"
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

const createCache = (configurations, configurationsErr) => {
    return {
        glue: {
            getSecurityConfigurations: {
                'us-east-1': {
                    err: configurationsErr,
                    data: configurations
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

describe('bookmarkEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if Glue security configuration has job bookmark encryption enabled', function (done) {
            const cache = createCache([getSecurityConfigurations[0]]);
            bookmarkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Glue security configuration has job bookmark encryption disabled', function (done) {
            const cache = createCache([getSecurityConfigurations[1]]);
            bookmarkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No AWS security configurations found', function (done) {
            const cache = createCache([]);
            bookmarkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to get Glue security configurations', function (done) {
            const cache = createCache(null, { message: "Unable to get security configurations" });
            bookmarkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get security configurations response not found', function (done) {
            const cache = createNullCache();
            bookmarkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
}); 