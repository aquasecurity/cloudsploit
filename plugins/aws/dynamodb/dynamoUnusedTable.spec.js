var expect = require('chai').expect;
const dynamoUnusedTable = require('./dynamoUnusedTable');

const listTables = [
    "akd-03"
];

const describeTable = [
    {
        "Table": {
            "ItemCount": 0
        }
    },
    {
        "Table": {
            "ItemCount": 1
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
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '1111222222222'
                }
            }
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

describe('dynamoUnusedTable', function () {
    describe('run', function () {
        it('should PASS if DynamoDB table is being used', function (done) {
            const cache = createCache(listTables, describeTable[1]);
            dynamoUnusedTable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DynamoDB table "akd-03" is being used');
                done();
            });
        });

        it('should FAIL if DynamoDB table is not used', function (done) {
            const cache = createCache(listTables, describeTable[0]);
            dynamoUnusedTable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DynamoDB table "akd-03" is empty');
                done();
            });
        });

        it('should PASS if No DynamoDB tables found', function (done) {
            const cache = createCache([], describeTable[1]);
            dynamoUnusedTable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DynamoDB tables found');
                done();
            });
        });

        it('should UNKNOWN if unable to list DynamoDB tables', function (done) {
            const cache = createErrorCache();
            dynamoUnusedTable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for DynamoDB tables');
                done();
            });
        });

        it('should UNKNOWN if unable to describe DynamoDB table', function (done) {
            const cache = createCache(listTables);
            dynamoUnusedTable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to describe DynamoDB table');
                done();
            });
        });
    });
});
