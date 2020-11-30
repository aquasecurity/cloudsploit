const expect = require('chai').expect;
const ebsSnapshotLifecycle = require('./ebsSnapshotLifecycle');

const describeInstances = [
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-02cd6ecf4fb6f634d",
                "InstanceType": "t2.micro",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2020-10-14T22:57:34.000Z",
                            "DeleteOnTermination": true,
                            "Status": "attached",
                            "VolumeId": "vol-02f1886d6c361b9d5"
                        }
                    }
                ],
                "Tags": [
                    {
                        "Key": "env",
                        "Value": "prod"
                    }
                ]
            }
        ],
        "OwnerId": "112233445566",
        "ReservationId": "r-06b211b02d99a6a2d"
    }
];

const describeVolumes = [
    {
        "Attachments": [],
        "AvailabilityZone": "us-east-1a",
        "CreateTime": "2020-09-09T14:30:42.601Z",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0",
        "Size": 1,
        "SnapshotId": "",
        "State": "available",
        "VolumeId": "vol-0065e2a7632d0d083",
        "Iops": 100,
        "Tags": [
            {
                "Key": "env",
                "Value": "prod"
            }
        ],
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    },
    {
        "Attachments": [
            {
                "AttachTime": "2020-10-14T22:57:34.000Z",
                "Device": "/dev/xvda",
                "InstanceId": "i-02cd6ecf4fb6f634d",
                "State": "attached",
                "VolumeId": "vol-02f1886d6c361b9d5",
                "DeleteOnTermination": true
            }
        ],
        "AvailabilityZone": "us-east-1e",
        "CreateTime": "2020-10-14T22:57:34.416Z",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0",
        "Size": 8,
        "SnapshotId": "snap-0299d083f0ce6cd12",
        "State": "in-use",
        "VolumeId": "vol-02f1886d6c361b9d5",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    }
];

const getLifecyclePolicies = [
    {
        "PolicyId": "policy-061754468570a2ed1",
        "Description": "test-policy-1",
        "State": "ENABLED",
        "Tags": {}
    }
];

const getLifecyclePolicy = [
    {
        "Policy": {
            "PolicyId": "policy-061754468570a2ed1",
            "Description": "test-policy-1",
            "State": "ENABLED",
            "StatusMessage": "ENABLED",
            "ExecutionRoleArn": "arn:aws:iam::112233445566:role/service-role/AWSDataLifecycleManagerDefaultRole",
            "DateCreated": 1604050465.702,
            "DateModified": 1604050465.834,
            "PolicyDetails": {
                "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
                "ResourceTypes": [
                    "VOLUME"
                ],
                "TargetTags": [
                    {
                        "Key": "env",
                        "Value": "prod"
                    }
                ],
                "Schedules": [
                    {
                        "Name": "Schedule 1",
                        "CopyTags": false,
                        "CreateRule": {
                            "Interval": 12,
                            "IntervalUnit": "HOURS",
                            "Times": [
                                "09:00"
                            ]
                        },
                        "RetainRule": {
                            "Count": 2,
                            "Interval": 0
                        }
                    }
                ]
            },
            "PolicyArn": "arn:aws:dlm:us-east-1:112233445566:policy/policy-061754468570a2ed1"
        }
    }
];

const createCache = (describeVolumes, describeInstances, getLifecyclePolicies, getLifecyclePolicy) => {
    var policyId = (getLifecyclePolicies && getLifecyclePolicies.length) ? getLifecyclePolicies[0].PolicyId : null
    return {
        ec2: {
            describeVolumes: {
                'us-east-1': {
                    data: describeVolumes
                }
            },
            describeInstances: {
                'us-east-1': {
                    data: describeInstances
                }
            }
        },
        dlm: {
            getLifecyclePolicies: {
                'us-east-1': {
                    data: getLifecyclePolicies
                }
            },
            getLifecyclePolicy: {
                'us-east-1': {
                    [policyId]: {
                        data: getLifecyclePolicy
                    }
                }
            }
        }
    };
}

const createErrorCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing ec2 instances'
                    },
                },
            },
            describeVolumes: {
                'us-east-1': {
                    err: {
                        message: 'error describing ebs volumes'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': null,
            },
            describeVolumes: {
                'us-east-1': null,
            },
        },
    };
};

describe('ebsSnapshotLifecycle', function () {
    describe('run', function () {
        it('should PASS if EBS volume has lifecycle policy configures', function (done) {
            const cache = createCache([describeVolumes[0]], describeInstances, getLifecyclePolicies, getLifecyclePolicy[0]);
            ebsSnapshotLifecycle.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if EBS volume does not have lifecycle policy configured', function (done) {
            const cache = createCache([describeVolumes[1]], [describeInstances[0]], getLifecyclePolicies, getLifecyclePolicy[0]);
            ebsSnapshotLifecycle.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if no EBS volumes found', function (done) {
            const cache = createCache([]);
            ebsSnapshotLifecycle.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if describe EC2 instances or EBS volumes response not found', function (done) {
            const cache = createNullCache();
            ebsSnapshotLifecycle.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe EC2 instances or EBS volumes', function (done) {
            const cache = createErrorCache();
            ebsSnapshotLifecycle.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});