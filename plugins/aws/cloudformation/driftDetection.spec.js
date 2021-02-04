var expect = require('chai').expect;
const driftDetection = require('./driftDetection');

const listStacks = [
    {
        "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "StackName": "AKD",
        "CreationTime": "2020-12-05T19:49:48.498000+00:00",
        "StackStatus": "CREATE_COMPLETE",
        "DriftInformation": {
            "StackDriftStatus": "IN_SYNC",
            "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
        }
    },
    {
        "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "StackName": "AKD",
        "CreationTime": "2020-12-05T19:49:48.498000+00:00",
        "StackStatus": "CREATE_COMPLETE",
        "DriftInformation": {
            "StackDriftStatus": "DRIFTED",
            "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
        }
    },
];

const createCache = (stacks) => {
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    data: stacks
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    err: {
                        message: 'error listing CloudFormation stacks'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': null,
            },
        },
    };
};

describe('driftDetection', function () {
    describe('run', function () {
        it('should PASS if CloudFormation stack is not in drifted state', function (done) {
            const cache = createCache([listStacks[0]]);
            driftDetection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudFormation stack is in drifted state', function (done) {
            const cache = createCache([listStacks[1]]);
            driftDetection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no CloudFormation stacks found', function (done) {
            const cache = createCache([]);
            driftDetection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list stacks', function (done) {
            const cache = createErrorCache();
            driftDetection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list stacks response not found', function (done) {
            const cache = createNullCache();
            driftDetection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});