var expect = require('chai').expect;
var flowEncrypted = require('./flowEncrypted');

const listFlows = [
    {
        "flowArn": "arn:aws:appflow:us-east-1:000011112222:flow/test-flow",
        "description": null,
        "flowName": "test-flow",
        "flowStatus": "Active",
        "sourceConnectorType": "S3",
        "destinationConnectorType": "S3",
        "triggerType": "OnDemand",
        "createdAt": "2021-11-08T14:13:50.894Z",
        "lastUpdatedAt": "2021-11-08T14:25:30.775Z",
        "createdBy": "arn:aws:iam::000011112222:user/aqua.cloudsploit",
        "lastUpdatedBy": "arn:aws:iam::000011112222:user/aqua.cloudsploit",
        "tags": {}
    }
];

const describeFlow = [
    {
        "flowArn": "arn:aws:appflow:us-east-1:000011112222:flow/test-flow",
        "description": null,
        "flowName": "test-flow",
        "kmsArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
        "flowStatus": "Active",
        "flowStatusMessage": null,
        "sourceFlowConfig": {
          "connectorType": "S3",
          "connectorProfileName": null,
          "sourceConnectorProperties": {
            "S3": {
              "bucketName": "test-data-bucket",
              "bucketPrefix": "data/"
            }
          }
        },
        "destinationFlowConfigList": [
          {
            "connectorType": "S3",
            "connectorProfileName": null,
            "destinationConnectorProperties": {
              "S3": {
                "bucketName": "test-data-bucket",
                "bucketPrefix": "data",
                "s3OutputFormatConfig": {
                  "fileType": "JSON",
                  "prefixConfig": {
                    "prefixType": null,
                    "prefixFormat": null
                  },
                  "aggregationConfig": {
                    "aggregationType": "None"
                  }
                }
              }
            }
          }
        ],
        "triggerConfig": {
          "triggerType": "OnDemand",
          "triggerProperties": {}
        },
        "tasks": [
          {
            "sourceFields": [
              "uuid_id",
              "timestamp"
            ],
            "connectorOperator": {
              "Amplitude": null,
              "Datadog": null,
              "Dynatrace": null,
              "GoogleAnalytics": null,
              "InforNexus": null,
              "Marketo": null,
              "S3": "PROJECTION",
              "Salesforce": null,
              "ServiceNow": null,
              "Singular": null,
              "Slack": null,
              "Trendmicro": null,
              "Veeva": null,
              "Zendesk": null,
              "SAPOData": null
            },
            "destinationField": null,
            "taskType": "Filter",
            "taskProperties": {}
          },
          {
            "sourceFields": [
              "uuid_id"
            ],
            "connectorOperator": {
              "Amplitude": null,
              "Datadog": null,
              "Dynatrace": null,
              "GoogleAnalytics": null,
              "InforNexus": null,
              "Marketo": null,
              "S3": "NO_OP",
              "Salesforce": null,
              "ServiceNow": null,
              "Singular": null,
              "Slack": null,
              "Trendmicro": null,
              "Veeva": null,
              "Zendesk": null,
              "SAPOData": null
            },
            "destinationField": "uuid_id",
            "taskType": "Map",
            "taskProperties": {}
          },
          {
            "sourceFields": [
              "timestamp"
            ],
            "connectorOperator": {
              "Amplitude": null,
              "Datadog": null,
              "Dynatrace": null,
              "GoogleAnalytics": null,
              "InforNexus": null,
              "Marketo": null,
              "S3": "NO_OP",
              "Salesforce": null,
              "ServiceNow": null,
              "Singular": null,
              "Slack": null,
              "Trendmicro": null,
              "Veeva": null,
              "Zendesk": null,
              "SAPOData": null
            },
            "destinationField": "timestamp",
            "taskType": "Map",
            "taskProperties": {}
          }
        ],
        "createdAt": "2021-11-08T14:13:50.894Z",
        "lastUpdatedAt": "2021-11-08T14:25:30.775Z",
        "createdBy": "arn:aws:iam::000011112222:user/aqua.cloudsploit",
        "lastUpdatedBy": "arn:aws:iam::000011112222:user/aqua.cloudsploit",
        "tags": {}
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
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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

const createCache = (flows, keys, describeFlow, describeKey, flowsErr, keysErr, describeKeyErr, describeFlowErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyArn.split('/')[1] : null;
    var flowName = (flows && flows.length) ? flows[0].flowName: null;
    return {
        appflow: {
            listFlows: {
                'us-east-1': {
                    err: flowsErr,
                    data: flows
                },
            },
            describeFlow: {
                'us-east-1': {
                    [flowName]: {
                        data: describeFlow,
                        err: describeFlowErr
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

describe('flowEncrypted', function () {
    describe('run', function () {
        it('should PASS if AppFlow flow is encrypted with desired encryption level', function (done) {
            const cache = createCache(listFlows, listKeys, describeFlow[0], describeKey[0]);
            flowEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if AppFlow flow is not encrypted with desired encryption level', function (done) {
            const cache = createCache(listFlows, listKeys, describeFlow[0], describeKey[1]);
            flowEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no AppFlow flows found', function (done) {
            const cache = createCache([]);
            flowEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list AppFlow flows', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list AppFlow flows" });
            flowEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listFlows, null, null, null, { message: "Unable to list KMS keys" });
            flowEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})