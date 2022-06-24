let expect = require('chai').expect;
let ebsBackupEnabled = require('./ebsBackupEnabled');

const describeVolumes = [
    {
        "Attachments": [],
        "AvailabilityZone": "us-east-1d",
        "CreateTime": "2020-09-01T03:40:13.595Z",
        "Encrypted": false,
        "Size": 8,
        "SnapshotId": "snap-06d919bfeced8496a",
        "State": "available",
        "VolumeId": "vol-0d7619e666a54b52a",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    },
    {
        "Attachments": [
            {
                "AttachTime": "2020-08-25T02:21:49.000Z",
                "Device": "/dev/xvda",
                "InstanceId": "i-03afb9daa31f31bb0",
                "State": "attached",
                "VolumeId": "vol-025b523c155020b10",
                "DeleteOnTermination": true
            }
        ],
        "AvailabilityZone": "us-east-1e",
        "CreateTime": "2020-08-25T02:21:49.073Z",
        "Encrypted": false,
        "Size": 8,
        "SnapshotId": "snap-06d919bfeced8496a",
        "State": "in-use",
        "VolumeId": "vol-025b523c155020b10",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    },
    {
        "Attachments": [
            {
                "AttachTime": "2020-08-25T02:21:49.000Z",
                "Device": "/dev/xvda",
                "InstanceId": "i-0ceecc81a1c5829f6",
                "State": "attached",
                "VolumeId": "vol-025b523c155020b10",
                "DeleteOnTermination": true
            }
        ],
        "AvailabilityZone": "us-east-1e",
        "CreateTime": "2020-08-25T02:21:49.073Z",
        "Encrypted": false,
        "Size": 8,
        "SnapshotId": "snap-06d919bfeced8496a",
        "State": "in-use",
        "VolumeId": "vol-025b523c155020b10",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    }
]

const describeSnapshots = [
    {
        "Description": "Created for testing",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/c48d9687-cdd3-4a1f-9d80-f92a7693c5d0",
        "OwnerId": "112233445566",
        "Progress": "100%",
        "SnapshotId": "snap-00317ba0e33942c5a",
        "StartTime": "2020-8-31T11:40:33.066Z",
        "State": "completed",
        "VolumeId": "vol-0d7619e666a54b52a",
        "VolumeSize": 1,
        "Tags": []
    },
    {
        "Description": "Created for testing",
        "Encrypted": false,
        "OwnerId": "112233445566",
        "Progress": "100%",
        "SnapshotId": "snap-03fb4402f29407fa0",
        "StartTime": "2020-10-31T11:40:33.066Z",
        "State": "completed",
        "VolumeId": "vol-0065e2a7632d0d083",
        "VolumeSize": 1,
        "Tags": []
    }
];

const describeInstances = [
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0ceecc81a1c5829f6",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-11-09T21:27:25.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1b",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PublicIpAddress": "3.84.159.125",
                "State": {
                    "Code": 0,
                    "Name": "running"
                },
                "StateTransitionReason": "",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "InstanceLifecycle": "spot"
            }
        ]
    },
];

const createCache = (volumes, snapshots, instances) => {
    return {
        ec2:{
            describeSnapshots: {
                'us-east-1': {
                    data: snapshots
                },
            },
            describeVolumes: {
                'us-east-1': {
                    data: volumes
                },
            },
            describeInstances: {
                'us-east-1': {
                    data: instances
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeSnapshots: {
                'us-east-1': {
                    err: {
                        message: 'error describing snapshots'
                    },
                },
            },
            describeVolumes: {
                'us-east-1': {
                    data: 'error describing volumes'
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSnapshots: {
                'us-east-1': null
            },
            describeVolumes: {
                'us-east-1': null
            }
        },
    };
};

describe('ebsBackupEnabled', function () {
    describe('run', function () {
        it('should PASS if EBS snapshots found', function (done) {
            const cache = createCache([describeVolumes[0]], [describeSnapshots[0]], describeInstances);
            ebsBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        it('should not return anything if EBS volume is attached to a spot instance', function (done) {
            const cache = createCache([describeVolumes[2]], [describeSnapshots[0]], describeInstances);
            ebsBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        it('should PASS if snapshot for 1 volume is found and not found for another', function (done) {
            const cache = createCache(describeVolumes, describeSnapshots, describeInstances);
            ebsBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(2);
                done();
            });
        });
        it('should UNKNOWN if error occurs while describe EBS snapshots or EBS volumes', function (done) {
            const cache = createErrorCache();
            ebsBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        it('should not return any results if unable to fetch EBS snapshots or EBS volumes', function (done) {
            const cache = createNullCache();
            ebsBackupEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});