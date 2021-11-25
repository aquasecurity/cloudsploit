var expect = require('chai').expect;
var environmentDataEncrypted = require('./environmentDataEncrypted');

const listEnvironments = [    
    "MyAirflowEnvironment", 
];

const getEnvironment = [
    {
        "Environment": {
            "AirflowConfigurationOptions": {},
            "AirflowVersion": "2.0.2",
            "Arn": "arn:aws:airflow:us-east-1:000111222333:environment/MyAirflowEnvironment",
            "CreatedAt": "2021-11-16T17:29:30+05:00",
            "DagS3Path": "data",
            "EnvironmentClass": "mw1.small",
            "ExecutionRoleArn": "arn:aws:iam::000111222333:role/service-role/AmazonMWAA-MyAirflowEnvironment-CKkXBd",
            "KmsKey": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "LastUpdate": {
                "CreatedAt": "2021-11-16T17:29:30+05:00",
                "Error": {
                    "ErrorCode": "INCORRECT_CONFIGURATION",
                    "ErrorMessage": "You may need to check the execution role permissions policy for your environment, and that each of the VPC networking components required by the environment are configured to allow traffic. Troubleshooting: https://docs.aws.amazon.com/mwaa/latest/userguide/troubleshooting.html"
                },
                "Status": "FAILED"
            },
            "LoggingConfiguration": {
                "DagProcessingLogs": {
                    "Enabled": false,
                    "LogLevel": "WARNING"
                },
                "SchedulerLogs": {
                    "Enabled": false,
                    "LogLevel": "WARNING"
                },
                "TaskLogs": {
                    "Enabled": true,
                    "LogLevel": "INFO"
                },
                "WebserverLogs": {
                    "Enabled": false,
                    "LogLevel": "WARNING"
                },
                "WorkerLogs": {
                    "Enabled": false,
                    "LogLevel": "WARNING"
                }
            },
            "MaxWorkers": 10,
            "MinWorkers": 1,
            "Name": "MyAirflowEnvironment",
        }
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
]

const createCache = (environments, keys, getEnvironment, describeKey, environmentsErr, keysErr, describeKeyErr, getEnvironmentErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var environment = (environments && environments.length) ? environments[0]: null;
    return {
        mwaa: {
            listEnvironments: {
                'us-east-1': {
                    err: environmentsErr,
                    data: environments
                },
            },
            getEnvironment: {
                'us-east-1': {
                    [environment]: {
                        data: getEnvironment,
                        err: getEnvironmentErr
                    }
                }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('environmentDataEncrypted', function () {
    describe('run', function () {
        it('should PASS if MWAA Environment Data is encrypted with desired encryption level', function (done) {
            const cache = createCache(listEnvironments, listKeys, getEnvironment[0], describeKey[0]);
            environmentDataEncrypted.run(cache, { mwaa_environmentdata_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MWAA Environment Data is not encrypted with desired encryption level', function (done) {
            const cache = createCache(listEnvironments,listKeys, getEnvironment[0], describeKey[1]);
            environmentDataEncrypted.run(cache, { mwaa_environmentdata_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no MWAA Environment found', function (done) {
            const cache = createCache([]);
            environmentDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MWAA Environment', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list MWAA Environment" });
            environmentDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listEnvironments, null, null, null, { message: "Unable to list KMS keys" });
            environmentDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})