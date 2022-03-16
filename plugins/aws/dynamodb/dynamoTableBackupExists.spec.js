var expect = require('chai').expect;
const dynamoTableBackupExists = require('./dynamoTableBackupExists');

const listTables = [
    "mine1",
    "sadeedTable"
];

const listBackups = [
    {
        "BackupSummaries": [
            {
                "TableName": "sadeedTable",
                "TableId": "a8077fa1-cb2a-473f-87e2-c776849ba4a5",
                "TableArn": "arn:aws:dynamodb:us-east-1:000011112222:table/sadeedTable",
                "BackupArn": "arn:aws:dynamodb:us-east-1:000011112222:table/sadeedTable/backup/01646839091311-17886cd9",
                "BackupName": "backup1",
                "BackupCreationDateTime": "2022-03-09T20:18:11.311000+05:00",
                "BackupStatus": "AVAILABLE",
                "BackupType": "USER",
                "BackupSizeBytes": 0
            }
        ]
    },
    {
        "BackupSummaries": []
    }
];

const createCache = (table, backups) => {
    return {
        dynamodb:{
            listTables: {
                'us-east-1': {
                    data: table
                },
            },
            listBackups: {
                'us-east-1': {
                    [table]: {
                        data: backups
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        dynamodb:{
            listTables: {
                'us-east-1': {
                    err: {
                        message: 'error listing DynamoDB tables'
                    },
                },
            },
            listBackups: {
                'us-east-1': {
                    err: {
                        message: 'error describing property'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        dynamodb:{
            listTables: {
                'us-east-1': null,
            },
            listBackups: {
                'us-east-1': null,
            },
        },
    };
};

describe('dynamoTableBackupExists', function () {
    describe('run', function () {
        it('should FAIL if no backup exists for DynamoDB table', function (done) {
            const cache = createCache([listTables[0]], listBackups[1]);
            dynamoTableBackupExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No backup exists for DynamoDB table')
                done();
            });
        });

        it('should PASS if backup exists for DynamoDB table', function (done) {
            const cache = createCache([listTables[1]], listBackups[0]);
            dynamoTableBackupExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Backup exists for DynamoDB table')
                done();
            });
        });

        it('should PASS No DynamoDB tables found', function (done) {
            const cache = createCache([]);
            dynamoTableBackupExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DynamoDB tables found')
                done();
            });
        });

        it('should UNKNOWN if Unable to query for DynamoDB tables', function (done) {
            const cache = createErrorCache();
            dynamoTableBackupExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for DynamoDB tables')
                done();
            });
        });

        it('should not return any results if list listTables response not found', function (done) {
            const cache = createNullCache();
            dynamoTableBackupExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
