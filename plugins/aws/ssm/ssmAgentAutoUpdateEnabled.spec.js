var expect = require('chai').expect;
const ssmAgentAutoUpdateEnabled = require('./ssmAgentAutoUpdateEnabled');

const describeInstanceInformation = [
    {
        "InstanceId": "i-0c8993c98fdb46a97",
        "PingStatus": "Online",
        "LastPingDateTime": 1599395666.201,
        "AgentVersion": "2.3.1644.0",
        "IsLatestVersion": true,
        "PlatformType": "Linux",
        "PlatformName": "Amazon Linux",
        "PlatformVersion": "2",
        "ResourceType": "EC2Instance",
        "IPAddress": "172.31.44.20",
        "ComputerName": "ip-172-31-44-20.ec2.internal",
        "AssociationStatus": "Success",
        "LastAssociationExecutionDate": 1599393759.647,
        "LastSuccessfulAssociationExecutionDate": 1599393759.647,
        "AssociationOverview": {
            "DetailedStatus": "Success",
            "InstanceAssociationStatusAggregatedCount": {
                "Success": 2
            }
        }
    }
];

const listAssociations = [
    {
        "Name": "AWS-UpdateSSMAgent",
        "AssociationId": "fbf42ad7-0e04-45e4-9a95-b5bea99fa311",
        "AssociationVersion": "2",
        "DocumentVersion": "$DEFAULT",
        "Targets": [
            {
                "Key": "InstanceIds",
                "Values": [
                    "*"
                ]
            }
        ],
        "LastExecutionDate": 1599393759.647,
        "Overview": {
            "Status": "Success",
            "DetailedStatus": "Success",
            "AssociationStatusAggregatedCount": {
                "Success": 1
            }
        },
        "ScheduleExpression": "rate(30 days)",
        "AssociationName": "test-asso-959"
    },
    {
        "Name": "AWS-UpdateSSMAgent",
        "AssociationId": "fbf42ad7-0e04-45e4-9a95-b5bea99fa311",
        "AssociationVersion": "2",
        "DocumentVersion": "$DEFAULT",
        "Targets": [
            {
                "Key": "InstanceIds",
                "Values": [
                    "*"
                ]
            }
        ],
        "LastExecutionDate": 1599393759.647,
        "Overview": {
            "Status": "Success",
            "DetailedStatus": "Success",
            "AssociationStatusAggregatedCount": {
                "Success": 1
            }
        },
        "AssociationName": "test-asso-959"
    },
    {
        "Name": "AWS-AttachEBSVolume",
        "AssociationId": "a068476e-b759-478e-9ea0-d61e4381fefe",
        "AssociationVersion": "1",
        "Targets": [
            {
                "Key": "aws:NoOpAutomationTag",
                "Values": [
                    "AWS-NoOpAutomationTarget-Value"
                ]
            }
        ],
        "LastExecutionDate": 1599378755.529,
        "Overview": {
            "Status": "Failed",
            "DetailedStatus": "InvalidAutomationParameters",
            "AssociationStatusAggregatedCount": {}
        },
        "AssociationName": "test1-947"
    }
];

const createCache = (instances, associations) => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    data: instances
                },
            },
            listAssociations: {
                'us-east-1': {
                    data: associations
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    err: {
                        message: 'error describing instance information'
                    },
                },
            },
            listAssociations: {
                'us-east-1': {
                    err: {
                        message: 'error listing associations'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': null,
            },
            listAssociations: {
                'us-east-1': null,
            },
        },
    };
};

describe('ssmAgentAutoUpdateEnabled', function () {
    describe('run', function () {
        it('should PASS if SSM Agent has SSM Agent auto update enabled', function (done) {
            const cache = createCache([describeInstanceInformation[0]], listAssociations);
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instance does not have SSM Agent auto update enabled', function (done) {
            const cache = createCache([describeInstanceInformation[0]], listAssociations[1]);
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no managed instances found', function (done) {
            const cache = createCache([], []);
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error while fetching instance information', function (done) {
            const cache = createErrorCache();
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to fetch any instance information', function (done) {
            const cache = createNullCache();
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
