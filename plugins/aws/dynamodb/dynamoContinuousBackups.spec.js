var expect = require('chai').expect;
const continuousBackups = require('./dynamoContinuousBackups');

const listTables = [
    "akd-03"
];

const describeContinuousBackups = [
    {
        "ContinuousBackupsDescription": {
            "ContinuousBackupsStatus": "ENABLED",
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED",
                "EarliestRestorableDateTime": "2020-11-25T04:44:48+05:00",
                "LatestRestorableDateTime": "2020-11-25T04:44:48+05:00"
            }
        }
    },
    {
        "ContinuousBackupsDescription":{
            "ContinuousBackupsStatus":"ENABLED",
            "PointInTimeRecoveryDescription":{
               "PointInTimeRecoveryStatus":"DISABLED"
            }
        }
    },
    {
        "ContinuousBackupsDescription":{
            "ContinuousBackupsStatus":"ENABLED",
        }
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
            describeContinuousBackups: {
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
            describeContinuousBackups: {
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
            describeContinuousBackups: {
                'us-east-1': null,
            },
        },
    };
};

describe('continuousBackups', function () {
    describe('run', function () {
        it('should PASS if DynamoDB table has continuous backups enabled', function (done) {
            const cache = createCache(listTables, describeContinuousBackups[0]);
            continuousBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if DynamoDB table does not have continuous backups enabled', function (done) {
            const cache = createCache(listTables, describeContinuousBackups[1]);
            continuousBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No DynamoDB tables found', function (done) {
            const cache = createCache([], describeContinuousBackups[1]);
            continuousBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list DynamoDB tables', function (done) {
            const cache = createErrorCache();
            continuousBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe DynamoDB table continuous backups', function (done) {
            const cache = createCache(listTables);
            continuousBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list tables response is not found', function (done) {
            const cache = createNullCache();
            continuousBackups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
