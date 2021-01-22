var expect = require('chai').expect;
const stackTerminationProtection = require('./stackTerminationProtection');

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
];

const describeStacks = [
    {
        "Stacks": [ 
            {
                "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                "StackName": "AKD",
                "CreationTime": "2020-12-05T19:49:48.498000+00:00",
                "RollbackConfiguration": {
                    "RollbackTriggers": []
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "NotificationARNs": ["arn:aws:sns:us-east-1:1234567890123456:mytopic"],
                "Tags": [],
                "EnableTerminationProtection": true,
                "DriftInformation": {
                    "StackDriftStatus": "IN_SYNC",
                    "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
                },
            }
        ]
    },
    {
        "Stacks": [ 
            {
                "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                "StackName": "AKD",
                "CreationTime": "2020-12-05T19:49:48.498000+00:00",
                "RollbackConfiguration": {
                    "RollbackTriggers": []
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "NotificationARNs": [],
                "Tags": [],
                "EnableTerminationProtection": false,
                "DriftInformation": {
                    "StackDriftStatus": "IN_SYNC",
                    "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
                }
            }
        ]
    }
]

const createCache = (stacks, stackDetails) => {
    var stackName = (stacks && stacks.length && stacks[0].StackName) ? stacks[0].StackName : null;
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    data: stacks
                },
            },
            describeStacks: {
                'us-east-1': {
                    [stackName]: {
                        data: stackDetails
                    },
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
            describeStacks: {
                'us-east-1': {
                    err: {
                        message: 'error describing CloudFormation stacks'
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
            describeStacks: {
                'us-east-1': null,
            },
        },
    };
};

describe('stackTerminationProtection', function () {
    describe('run', function () {
        it('should PASS if CloudFormation stack has SNS topic associated', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[0]);
            stackTerminationProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudFormation stack does not have SNS topic associated', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[1]);
            stackTerminationProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no CloudFormation stacks found', function (done) {
            const cache = createCache([]);
            stackTerminationProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if No stack details found', function (done) {
            const cache = createCache([listStacks[0]], {"Stacks": [] });
            stackTerminationProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list stacks', function (done) {
            const cache = createErrorCache();
            stackTerminationProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe stacks', function (done) {
            const cache = createCache([listStacks[0]], []);
            stackTerminationProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list stacks response is not found', function (done) {
            const cache = createNullCache();
            stackTerminationProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});