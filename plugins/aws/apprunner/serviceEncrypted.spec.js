var expect = require('chai').expect;
var serviceEncrypted = require('./serviceEncrypted');

const listServices = [
    {
        "ServiceName": "sadeed1",
        "ServiceId": "9110332340cc4be5963e467f5deae770",
        "ServiceArn": "arn:aws:apprunner:us-east-1:000111222333:service/sadeed1/9110332340cc4be5963e467f5deae770",
        "ServiceUrl": "znuqjfu7cp.us-east-1.awsapprunner.com",
        "CreatedAt": "2021-11-22T13:54:41+05:00",
        "UpdatedAt": "2021-11-22T13:54:41+05:00",
        "Status": "OPERATION_IN_PROGRESS"
    }
];

const describeService = [
    {
        "Service": {
            "ServiceName": "sadeed1",
            "ServiceId": "9110332340cc4be5963e467f5deae770",
            "ServiceArn": "arn:aws:apprunner:us-east-1:000111222333:service/sadeed1/9110332340cc4be5963e467f5deae770",
            "ServiceUrl": "znuqjfu7cp.us-east-1.awsapprunner.com",
            "CreatedAt": "2021-11-22T13:54:41+05:00",
            "UpdatedAt": "2021-11-22T13:54:41+05:00",
            "Status": "OPERATION_IN_PROGRESS",
            "SourceConfiguration": {
                "CodeRepository": {
                    "RepositoryUrl": "https://github.com/AkhtarAmir/DAIZIC-Assessment",
                    "SourceCodeVersion": {
                        "Type": "BRANCH",
                        "Value": "main"
                    },
                    "CodeConfiguration": {
                        "ConfigurationSource": "REPOSITORY"
                    }
                },
                "AutoDeploymentsEnabled": false,
                "AuthenticationConfiguration": {
                    "ConnectionArn": "arn:aws:apprunner:us-east-1:101363889637:connection/apprunner-connection/5497e544592748d29d92b57252d791b0"
                }
            },
            "InstanceConfiguration": {
                "Cpu": "1024",
                "Memory": "2048"
            },
            "EncryptionConfiguration": {
                "KmsKey": "arn:aws:kms:us-east-1:101363889637:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
            },
            "HealthCheckConfiguration": {
                "Protocol": "TCP",
                "Path": "/",
                "Interval": 10,
                "Timeout": 5,
                "HealthyThreshold": 1,
                "UnhealthyThreshold": 5
            },
            "AutoScalingConfigurationSummary": {
                "AutoScalingConfigurationArn": "arn:aws:apprunner:us-east-1:101363889637:autoscalingconfiguration/DefaultConfiguration/1/00000000000000000000000000000001",
                "AutoScalingConfigurationName": "DefaultConfiguration",
                "AutoScalingConfigurationRevision": 1
            }
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

const createCache = (services, keys, describeService, describeKey, servicesErr, keysErr, describeKeyErr, describeServiceErr) => {

    var keyId = (keys && keys.length ) ? keys[0].KeyId : null;
    var serviceArn = (services && services.length) ? services[0].ServiceArn: null;
    return {
        apprunner: {
            listServices: {
                'us-east-1': {
                    err: servicesErr,
                    data: services
                },
            },
            describeService: {
                'us-east-1': {
                    [serviceArn]: {
                        data: describeService,
                        err: describeServiceErr
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

describe('serviceEncrypted', function () {
    describe('run', function () {
        it('should PASS if App Runner service is encrypted with desired encryption level', function (done) {
            const cache = createCache([listServices[0]], listKeys, describeService[0], describeKey[0]);
            serviceEncrypted.run(cache, { app_runner_service_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if App Runner service not encrypted with desired encryption level', function (done) {
            const cache = createCache([listServices[0]],listKeys, describeService[0], describeKey[1]);
            serviceEncrypted.run(cache, { app_runner_service_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no App Runner service found', function (done) {
            const cache = createCache([]);
            serviceEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Services', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Services" });
            serviceEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listServices, null, null, null, { message: "Unable to list KMS keys" });
            serviceEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})