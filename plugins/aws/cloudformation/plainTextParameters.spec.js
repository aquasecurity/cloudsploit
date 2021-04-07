var expect = require('chai').expect;
const plaintextParameters = require('./plainTextParameters');

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
                "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                "StackName": "AKD",
                "Parameters": [
                    {
                        "ParameterKey": "Secret",
                        "ParameterValue": "bucketwithsecretparameter1"
                    },
                    {
                        "ParameterKey": "Password",
                        "ParameterValue": "bucketwithsecretparameter1"
                    }
                ],
                "CreationTime": "2020-08-13T13:34:52.435Z",
                "RollbackConfiguration": {
                    "RollbackTriggers": []
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "NotificationARNs": [],
                "Capabilities": [],
                "Outputs": [],
                "Tags": [],
                "DriftInformation": {
                    "StackDriftStatus": "NOT_CHECKED"
                }
            }]
    },
    {
        "Stacks": [
            {
                "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                "StackName": "AKD",
                "Parameters": [
                    {
                        "ParameterKey": "S3BucketName",
                        "ParameterValue": "testbucketplaintext1"
                    }
                ],
                "CreationTime": "2020-08-12T09:42:04.803Z",
                "RollbackConfiguration": {
                    "RollbackTriggers": [

                    ]
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "DriftInformation": {
                    "StackDriftStatus": "NOT_CHECKED"
                }
            }]
    },
    {
        "Stacks": [
            {
                "StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/AKD/081ed430-3733-11eb-a560-12e26def3eab",
                "StackName": "AKD",
                "Parameters": [
                    {
                        "ParameterKey": "Secret",
                        "ParameterValue": "****"
                    }
                ],
                "CreationTime": "2020-08-13T13:34:52.435Z",
                "RollbackConfiguration": {
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "DriftInformation": {
                    "StackDriftStatus": "NOT_CHECKED"
                }
            }]
    },
    {
        "Stacks": [
            {
                "StackId": "arn:aws:cloudformation:us-east-1:55005500:stack/TestStack/1493b310-dc80-11ea-b8ab-1214c28caebf",
                "StackName": "AKD",
                "Parameters": [],
                "CreationTime": "2020-08-12T09:42:04.803Z",
                "RollbackConfiguration": {
                },
                "StackStatus": "CREATE_COMPLETE",
                "DisableRollback": false,
                "DriftInformation": {
                    "StackDriftStatus": "NOT_CHECKED"
                }
            }]
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

describe('plaintextParameters', function () {
    describe('run', function () {
        it('should PASS if template does not contain any potentially-sensitive parameters', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[1]);
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if template contains any potentially-sensitive parameters but with NoEcho enabled', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[2]);
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if template contains any potentially-sensitive parameters', function (done) {
            const cache = createCache([listStacks[0]], describeStacks[0]);
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no CloudFormation stacks found', function (done) {
            const cache = createCache([]);
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list stacks', function (done) {
            const cache = createErrorCache();
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe stacks', function (done) {
            const cache = createCache([listStacks[0]], []);
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if no CloudFormation stack details found', function (done) {
            const cache = createCache([listStacks[0]], { "Stacks": [] });
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list stacks response is not found', function (done) {
            const cache = createNullCache();
            plaintextParameters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});