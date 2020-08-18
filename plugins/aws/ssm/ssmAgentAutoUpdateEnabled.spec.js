var expect = require('chai').expect;
const ssmAgentAutoUpdateEnabled = require('./ssmAgentAutoUpdateEnabled');

const instancesInformation = [
    {
        InstanceId: 'i-057f5422533f6e2d1',
        PingStatus: 'Online',
        LastPingDateTime: '2020-08-21T20:34:36.934Z',
        AgentVersion: '2.3.1644.0',
        IsLatestVersion: true,
        PlatformType: 'Linux',
        PlatformName: 'Amazon Linux',
        PlatformVersion: '2',
        ResourceType: 'EC2Instance',
        IPAddress: '172.31.48.168',
        ComputerName: 'ip-172-31-48-168.ec2.internal',
        AssociationStatus: 'Success',
        LastAssociationExecutionDate: '2020-08-21T19:54:48.550Z',
        LastSuccessfulAssociationExecutionDate: '2020-08-21T19:54:48.550Z',
        AssociationOverview: {
            DetailedStatus: 'Success',
            InstanceAssociationStatusAggregatedCount: { Success: 2 }
        }
    },
    {
        InstanceId: 'i-057f5422533f6e2d1',
        PingStatus: 'Online',
        LastPingDateTime: '2020-08-21T20:34:36.934Z',
        AgentVersion: '2.3.1644.0',
        IsLatestVersion: false,
        PlatformType: 'Linux',
        PlatformName: 'Amazon Linux',
        PlatformVersion: '2',
        ResourceType: 'EC2Instance',
        IPAddress: '172.31.48.168',
        ComputerName: 'ip-172-31-48-168.ec2.internal',
        AssociationStatus: 'Success',
        LastAssociationExecutionDate: '2020-08-21T19:54:48.550Z',
        LastSuccessfulAssociationExecutionDate: '2020-08-21T19:54:48.550Z',
        AssociationOverview: {
            DetailedStatus: 'Success',
            InstanceAssociationStatusAggregatedCount: { Success: 2 }
        }
    }
];

const createCache = (stacks) => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    data: stacks
                },
            },
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
        },
    };
};

const createNullCache = () => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': null,
            },
        },
    };
};

describe('ssmAgentAutoUpdateEnabled', function () {
    describe('run', function () {
        it('should PASS if ssm agent is set to auto update', function (done) {
            const cache = createCache([instancesInformation[0]]);
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ssm agent is not set to auto update', function (done) {
            const cache = createCache([instancesInformation[1]]);
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no instance found in ssm instance information', function (done) {
            const cache = createCache([]);
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
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

        it('should UNKNOWN if error occurs while fetching instance information', function (done) {
            const cache = createErrorCache();
            ssmAgentAutoUpdateEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});

C:\Users\Abdul\Documents\Projects\Aqua\scans>aws ssm describe-association --association-id 6f2d0558-6519-4ae7-98ea-010f0d6ed246
{
    "AssociationDescription": {
        "Name": "AWS-UpdateSSMAgent",
        "AssociationVersion": "2",
        "Date": 1598039643.583,
        "LastUpdateAssociationDate": 1598220090.665,
        "Overview": {
            "Status": "Success",
            "DetailedStatus": "Success",
            "AssociationStatusAggregatedCount": {
                "Success": 4
            }
        },
        "DocumentVersion": "$DEFAULT",
        "Parameters": {},
        "AssociationId": "6f2d0558-6519-4ae7-98ea-010f0d6ed246",
        "Targets": [
            {
                "Key": "InstanceIds",
                "Values": [
                    "*"
                ]
            }
        ],
        "ScheduleExpression": "rate(14 days)",
        "LastExecutionDate": 1598322467.814,
        "LastSuccessfulExecutionDate": 1598322467.814,
        "AssociationName": "SystemAssociationForSsmAgentUpdate",
        "ComplianceSeverity": "UNSPECIFIED",
        "ApplyOnlyAtCronInterval": false
    }
}

C:\Users\Abdul\Documents\Projects\Aqua\scans>aws ssm describe-association --association-id 6f2d0558-6519-4ae7-98ea-010f0d6ed246
{
    "AssociationDescription": {
        "Name": "AWS-UpdateSSMAgent",
        "AssociationVersion": "3",
        "Date": 1598039643.583,
        "LastUpdateAssociationDate": 1598322535.914,
        "Overview": {
            "Status": "Success",
            "DetailedStatus": "Success",
            "AssociationStatusAggregatedCount": {
                "Success": 1
            }
        },
        "DocumentVersion": "$DEFAULT",
        "Parameters": {
            "allowDowngrade": [
                "false"
            ],
            "version": [
                ""
            ]
        },
        "AssociationId": "6f2d0558-6519-4ae7-98ea-010f0d6ed246",
        "Targets": [
            {
                "Key": "InstanceIds",
                "Values": [
                    "*"
                ]
            }
        ],
        "LastExecutionDate": 1598322538.002,
        "LastSuccessfulExecutionDate": 1598322538.002,
        "AssociationName": "SystemAssociationForSsmAgentUpdate",
        "ComplianceSeverity": "UNSPECIFIED",
        "ApplyOnlyAtCronInterval": false
    }
}