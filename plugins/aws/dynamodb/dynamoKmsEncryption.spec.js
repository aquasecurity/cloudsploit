var expect = require('chai').expect;
const dynamoKmsEncryption = require('./dynamoKmsEncryption');

const tables = [
    "dynamo-table-1",
    "dynamo-table-2"
];

const describeTable = [
    {
        "Table": {
            "AttributeDefinitions": [
                {
                    "AttributeName": "id",
                    "AttributeType": "N"
                }
            ],
            "TableName": "dynamo-table-1",
            "KeySchema": [
                {
                    "AttributeName": "id",
                    "KeyType": "HASH"
                }
            ],
            "TableStatus": "ACTIVE",
            "CreationDateTime": 1605800911.034,
            "ProvisionedThroughput": {
                "NumberOfDecreasesToday": 0,
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5
            },
            "TableSizeBytes": 0,
            "ItemCount": 0,
            "TableArn": "arn:aws:dynamodb:us-east-1:112233445566:table/dynamo-table-1",
            "TableId": "abcef2b3-d76d-4ade-92bd-643d12545a20"
        },
    },
    {
        "Table": {
            "AttributeDefinitions": [
                {
                    "AttributeName": "id",
                    "AttributeType": "N"
                }
            ],
            "TableName": "dynamo-table-2",
            "KeySchema": [
                {
                    "AttributeName": "id",
                    "KeyType": "HASH"
                }
            ],
            "TableStatus": "ACTIVE",
            "CreationDateTime": 1605800911.034,
            "ProvisionedThroughput": {
                "NumberOfDecreasesToday": 0,
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5
            },
            "TableSizeBytes": 0,
            "ItemCount": 0,
            "TableArn": "arn:aws:dynamodb:us-east-1:112233445566:table/dynamo-table-2",
            "TableId": "dqe324wd-wer2-eeq3-92bd-3131e231wq",
            "SSEDescription": {
                "Status": "Enabled",
                "SSEType": "KMS",
                "KMSMasterKeyArn": "arn:aws:kms:us-east-1:112233445566:key/6be9b9f1-bbc3-47f8-91c7-d2c1bed8d90c"
            }
        }
    }
];

const createCache = (tables, describeTable) => {
    var tableName = (tables && tables.length) ? tables[0] : null;
    return {
        dynamodb: {
            listTables: {
                'us-east-1': {
                    data: tables,
                },
            },
            describeTable: {
                'us-east-1': {
                    [tableName]: {
                        data: describeTable
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        dynamodb: {
            listTables: {
                'us-east-1': {
                    err: {
                        message: 'error listing tables'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        dynamodb: {
            listTables: {
                'us-east-1': null,
            },
        },
    };
};

describe('dynamoKmsEncryption', function () {
    describe('run', function () {
        it('should FAIL if table is using default encryption with AWS-owned key', function (done) {
            const cache = createCache([tables[0]], describeTable[0]);
            dynamoKmsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if table encryption is enabled with a KMS master key', function (done) {
            const cache = createCache([tables[1]], describeTable[1]);
            dynamoKmsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no DynamoDB tables found', function (done) {
            const cache = createCache([]);
            dynamoKmsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for DynamoDB tables', function (done) {
            const cache = createErrorCache();
            dynamoKmsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list tables response not found', function (done) {
            const cache = createNullCache();
            dynamoKmsEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
