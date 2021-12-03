var expect = require('chai').expect;
var mqBrokerEncrypted = require('./mqBrokerEncrypted');

const listBrokers = [
    {
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:sadeed-br:b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerId": "b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerName": "sadeed-br",
        "BrokerState": "RUNNING",
        "Created": "2021-11-15T08:21:57.182000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "HostInstanceType": "mq.t3.micro"
    },
    {
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:sadeed-br3:b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerId": "b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerName": "sadeed-br3",
        "BrokerState": "RUNNING",
        "Created": "2021-11-15T09:58:29.997000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "HostInstanceType": "mq.t3.micro"
    },
    {
        "BrokerArn": "arn:aws:mq:us-east-1:101363889637:broker:mybr1:b-043833c7-190c-4ebf-bbe7-8d930f9f9124",
        "BrokerId": "b-043833c7-190c-4ebf-bbe7-8d930f9f9124",
        "BrokerName": "mybr1",
        "BrokerState": "CREATION_IN_PROGRESS",
        "Created": "2021-11-25T12:40:59.605000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "HostInstanceType": "mq.t3.micro"
    }
];

const describeBroker = [
    {
        "AuthenticationStrategy": "simple",
        "AutoMinorVersionUpgrade": true,
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:sadeed-br3:b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerId": "b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerInstances": [],
        "BrokerName": "sadeed-br3",
        "BrokerState": "CREATION_IN_PROGRESS",
        "Configurations": {
            "History": [],
            "Pending": {
                "Id": "c-7bee92e4-afc7-41aa-ad97-22a48d3ef090",
                "Revision": 1
            }
        },
        "Created": "2021-11-15T09:58:29.997000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EncryptionOptions": {
            "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/26fb32cb-1abc-4096-93eb-1fa0c6e6efb4",
            "UseAwsOwnedKey": false
        },
        "EngineType": "ActiveMQ",
        "EngineVersion": "5.16.3",
        "HostInstanceType": "mq.t3.micro",
    },
    {
        "AuthenticationStrategy": "simple",
        "AutoMinorVersionUpgrade": true,
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:sadeed-br:b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerId": "b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerInstances": [
            {
                "ConsoleURL": "https://b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4-1.mq.us-east-1.amazonaws.com:8162",
                "Endpoints": [
                    "ssl://b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4-1.mq.us-east-1.amazonaws.com:61617",
                    "amqp+ssl://b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4-1.mq.us-east-1.amazonaws.com:5671",
                    "stomp+ssl://b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4-1.mq.us-east-1.amazonaws.com:61614",
                    "mqtt+ssl://b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4-1.mq.us-east-1.amazonaws.com:8883",
                    "wss://b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4-1.mq.us-east-1.amazonaws.com:61619"
                ],
                "IpAddress": "172.31.90.204"
            }
        ],
        "BrokerName": "sadeed-br",
        "BrokerState": "RUNNING",
        "Configurations": {
            "Current": {
                "Id": "c-d76dd81d-cdba-4533-a71c-feeaf2e2606a",
                "Revision": 1
            },
            "History": []
        },
        "Created": "2021-11-15T08:21:57.182000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EncryptionOptions": {
            "KmsKeyId": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "UseAwsOwnedKey": false
        },
        "EngineType": "ActiveMQ",
        "EngineVersion": "5.16.3",
        "HostInstanceType": "mq.t3.micro",
    },
    {
        "AuthenticationStrategy": "simple",
        "AutoMinorVersionUpgrade": true,
        "BrokerArn": "arn:aws:mq:us-east-1:101363889637:broker:mybr1:b-043833c7-190c-4ebf-bbe7-8d930f9f9124",
        "BrokerId": "b-043833c7-190c-4ebf-bbe7-8d930f9f9124",
        "BrokerInstances": [],
        "BrokerName": "mybr1",
        "BrokerState": "CREATION_IN_PROGRESS",
        "Configurations": {
            "History": [],
            "Pending": {
                "Id": "c-babd5721-d60a-41b3-815a-d30b6fbfc0a3",
                "Revision": 1
            }
        },
        "Created": "2021-11-25T12:40:59.605000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EncryptionOptions": {
            "UseAwsOwnedKey": true
        },
        "EngineType": "ActiveMQ",
        "EngineVersion": "5.16.3",
        "HostInstanceType": "mq.t3.micro",
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/26fb32cb-1abc-4096-93eb-1fa0c6e6efb4",
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
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    }
]

const createCache = (brokers, keys, describeBroker, describeKey, brokersErr, keysErr, describeKeyErr, describeBrokerErr) => {
    var keyId = (keys && keys.length && keys[0].KmsKeyId) ? keys[0].KmsKeyId : null;
    var BrokerId = (brokers && brokers.length) ? brokers[0].BrokerId: null;
    return {
        mq: {
            listBrokers: {
                'us-east-1': {
                    err: brokersErr,
                    data: brokers
                },
            },
            describeBroker: {
                'us-east-1': {
                    [BrokerId]: {
                        data: describeBroker,
                        err: describeBrokerErr
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

describe('mqBrokerEncrypted', function () {
    describe('run', function () {
        it('should PASS if MQ Broker data at-rest is encrypted with desired encryption level', function (done) {
            const cache = createCache(listBrokers[0], listKeys, [describeBroker[1]], describeKey[0]);
            mqBrokerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MQ Broker data at-rest is not encrypted with desired encryption level', function (done) {
            const cache = createCache([listBrokers[1]],listKeys, [describeBroker[0]], describeKey[1]);
            mqBrokerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MQ Broker data at-rest is encrypted with AWS owned key', function (done) {
            const cache = createCache([listBrokers[2]],listKeys, [describeBroker[2]], describeKey[1]);
            mqBrokerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no MQ Broker found', function (done) {
            const cache = createCache([]);
            mqBrokerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MQ Broker', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list MQ Broker" });
            mqBrokerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listBrokers, null, null, null, { message: "Unable to list KMS keys" });
            mqBrokerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
