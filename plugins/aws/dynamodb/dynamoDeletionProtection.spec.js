var expect = require('chai').expect;
const dynamoDeletionProtection = require('./dynamoDeletionProtection');

const listTables = [
    "test-table"
];

const describeTable = [
    {
        "Table": {
            "DeletionProtectionEnabled": false
        }
    },
    {
        "Table": {
            "DeletionProtectionEnabled": true
        }
    },
];

const createCache = (table, details) => {
    return {
        dynamodb:{
            listTables: {
                'us-east-1': {
                    data: table
                },
            },
            describeTable: {
                'us-east-1': {
                    [table]: {
                        data: details
                    },
                },
            },
        }
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
            describeTable: {
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
            describeTable: {
                'us-east-1': null,
            },
        },
    };
};

describe('dynamoDeletionProtection', function () {
    describe('run', function () {
        it('should PASS if DynamoDB table has deletion protection enabled', function (done) {
            const cache = createCache(listTables, describeTable[1]);
            dynamoDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.include('us-east-1');
                expect(results[0].message).to.include('DynamoDB table "test-table" has deletion protection enabled');
                done();
            });
        });

        it('should FAIL if DynamoDB table does not have deletion protection enabled', function (done) {
            const cache = createCache(listTables, describeTable[0]);
            dynamoDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.include('us-east-1')
                expect(results[0].message).to.include('DynamoDB table "test-table" does not have deletion protection enabled');
                done();
            });
        });

        it('should PASS if No DynamoDB tables found', function (done) {
            const cache = createCache([], describeTable[1]);
            dynamoDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.include('us-east-1')
                expect(results[0].message).to.include('No DynamoDB tables found');
                done();
            });
        });

        it('should UNKNOWN if unable to list DynamoDB tables', function (done) {
            const cache = createErrorCache();
            dynamoDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                 expect(results[0].region).to.include('us-east-1')
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for DynamoDB tables');
                done();
            });
        });

        it('should UNKNOWN if unable to describe DynamoDB table', function (done) {
            const cache = createCache(listTables);
            dynamoDeletionProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.include('us-east-1')
                expect(results[0].message).to.include('Unable to describe DynamoDB table');
                done();
            });
        });
    });
});
