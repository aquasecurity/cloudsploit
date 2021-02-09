var expect = require('chai').expect;
const stackFailedStatus = require('./stackFailedStatus');

var stackFailTime = new Date();
stackFailTime.setMonth(stackFailTime.getMonth() - 1);

const listStacks = [
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "StackName": "AKD",
        "CreationTime": "2020-12-05T19:49:48.498000+00:00",
        "RollbackConfiguration": {
            "RollbackTriggers": []
        },
        "StackStatus": "CREATE_COMPLETE",
        "DisableRollback": false,
        "NotificationARNs": [],
        "Tags": [],
        "DriftInformation": {
            "StackDriftStatus": "IN_SYNC",
            "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
        }
    },
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "StackName": "AKD",
        "CreationTime": "2020-12-05T19:49:48.498000+00:00",
        "RollbackConfiguration": {
            "RollbackTriggers": []
        },
        "StackStatus": "CREATE_FAILED",
        "DisableRollback": false,
        "NotificationARNs": [],
        "Tags": [],
        "DriftInformation": {
            "StackDriftStatus": "DRIFTED",
            "LastCheckTimestamp": "2020-12-05T20:37:03.931000+00:00"
        }
    }
];

const describeStackEvents = [
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "EventId": "181744d0-3733-11eb-ba27-12d63bc7967b",
        "StackName": "AKD",
        "LogicalResourceId": "AKD",
        "PhysicalResourceId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "ResourceType": "AWS::CloudFormation::Stack",
        "Timestamp": new Date(),
        "ResourceStatus": "Create_Failed",
        "ClientRequestToken": "Console-CreateStack-7e419cb6-89e6-d631-1815-395a30eb1348"
    },
    {
        "StackId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "EventId": "181744d0-3733-11eb-ba27-12d63bc7967b",
        "StackName": "AKD",
        "LogicalResourceId": "AKD",
        "PhysicalResourceId": "arn:aws:cloudformation:us-east-1:000011112222:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
        "ResourceType": "AWS::CloudFormation::Stack",
        "Timestamp": stackFailTime,
        "ResourceStatus": "Create_Failed",
        "ClientRequestToken": "Console-CreateStack-7e419cb6-89e6-d631-1815-395a30eb1348"
    },
]

const createCache = (stack, events) => {
    var stackName = (stack && stack.length && stack[0].StackName) ? stack[0].StackName : null;
    return {
        cloudformation: {
            listStacks: {
                'us-east-1': {
                    data: stack
                },
            },
            describeStackEvents: {
                'us-east-1': {
                    [stackName]: {
                        data: {
                            StackEvents: events
                        },
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
                        message: 'error describing CloudFormation stacks'
                    },
                },
            },
            describeStackEvents: {
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
            describeStackEvents: {
                'us-east-1': null,
            },
        },
    };
};

describe('stackFailedStatus', function () {
    describe('run', function () {
        it('should PASS if CloudFormation stack is not in failed state', function (done) {
            const cache = createCache([listStacks[0]]);
            stackFailedStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if CloudFormation stack is in failed state for less than the failed hours limit', function (done) {
            const cache = createCache([listStacks[1]], [describeStackEvents[0]]);
            const settings = {failed_hours_limit: 10};

            stackFailedStatus.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if CloudFormation stack is in failed state for more than the failed hours limit', function (done) {
            const cache = createCache([listStacks[1]], [describeStackEvents[1]]);
            const settings = {failed_hours_limit: 10};

            stackFailedStatus.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no CloudFormation stacks found', function (done) {
            const cache = createCache([]);
            stackFailedStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe stacks', function (done) {
            const cache = createErrorCache();
            stackFailedStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if describe stacks response is not found', function (done) {
            const cache = createNullCache();
            stackFailedStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});