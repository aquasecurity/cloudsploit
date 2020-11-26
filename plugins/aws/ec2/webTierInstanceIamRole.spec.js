var expect = require('chai').expect;
const webTierInstanceIamRole = require('./webTierInstanceIamRole');

const describeInstances = [
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-11-18T22:48:08.000Z",
                "SubnetId": "subnet-aac6b3e7",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111222333444:instance-profile/test-role-1",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
                "Tags": [
                    {
                        "Key": "web-tier",
                        "Value": "web-tier"
                    }
                ],
            }
        ],
        "OwnerId": "111222333444",
        "ReservationId": "r-087ce52925d75c272"
    },
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-036d7bf13e0bfe836",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111222333444:instance-profile/test-ec2-role-2",
                    "Id": "AIPAYE32SRU5VWPEXDHQE"
                },
            }
        ],
        "OwnerId": "111222333444",
        "ReservationId": "r-1323e23rede231231"
    },
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-8ee72s82hsn2nw22w",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111222333444:instance-profile/test-ec2-role-3",
                    "Id": "AIPAYE32SRU5VWPKDMWKD"
                },
                "Tags": [
                    {
                        "Key": "web-tier",
                        "Value": "web-tier"
                    }
                ],
            }
        ],
        "OwnerId": "111222333444",
        "ReservationId": "r-d23ed2ed23wqe2r45"
    },
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-12f34r3refkn34irw",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "Tags": [
                    {
                        "Key": "web-tier",
                        "Value": "web-tier"
                    }
                ],
            }
        ],
        "OwnerId": "111222333444",
        "ReservationId": "r-0i09oijmi32e2q3e23"
    }
];

const describeTags = [
    {
        "Key": "web-tier",
        "ResourceId": "i-0e5b41e1d67462547",
        "ResourceType": "instance",
        "Value": "web-tier"
    },
    {
        "Key": "web-tier",
        "ResourceId": "i-8ee72s82hsn2nw22w",
        "ResourceType": "instance",
        "Value": "web-tier"
    },
    {
        "Key": "web-tier",
        "ResourceId": "i-12f34r3refkn34irw",
        "ResourceType": "instance",
        "Value": "web-tier"
    }
];

const listRoles = [
    {
        "Path": "/",
        "RoleName": "test-role-1",
        "RoleId": "AROAYE32SRU5734GJYW4F",
        "Arn": "arn:aws:iam::111222333444:role/test-role-1",
        "CreateDate": "2020-08-20T17:42:55Z",
        "AssumeRolePolicyDocument": {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-2",
        "RoleId": "AROAYE32SRU5734GJYW4F",
        "Arn": "arn:aws:iam::111222333444:role/test-role-2",
        "CreateDate": "2020-08-20T17:42:55Z",
        "AssumeRolePolicyDocument": {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
    {
        "Path": "/",
        "RoleName": "test-role-3",
        "RoleId": "AROAYE32SRU5734GJYW4F",
        "Arn": "arn:aws:iam::111222333444:role/test-role-3",
        "CreateDate": "2020-08-20T17:42:55Z",
        "AssumeRolePolicyDocument": {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "MaxSessionDuration": 3600
    },
];

const listRolePolicies = [
    {
        "PolicyNames": [
            {
                "PolicyName": "AWSElasticBeanstalkWebTier",
                "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
            },
            {
                "PolicyName": "AWSElasticBeanstalkMulticontainerDocker",
                "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkMulticontainerDocker"
            },
            {
                "PolicyName": "AWSElasticBeanstalkWorkerTier",
                "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier"
            }
        ]
    },
    {
        "PolicyNames": []
    }
];

const listAttachedRolePolicies = [
    {
        "AttachedPolicies": [
            {
                "PolicyName": "AWSElasticBeanstalkWebTier",
                "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
            },
            {
                "PolicyName": "AWSElasticBeanstalkMulticontainerDocker",
                "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkMulticontainerDocker"
            },
            {
                "PolicyName": "AWSElasticBeanstalkWorkerTier",
                "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier"
            }
        ]
    },
    {
        "AttachedPolicies": []
    }
];

const createCache = (describeInstances, describeTags, listRoles, listRolePolicies, listAttachedRolePolicies) => {
    var roleName = (listRoles && listRoles.length) ? listRoles[0].RoleName : null;
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: describeInstances
                },
            },
            describeTags: {
                'us-east-1': {
                    data: describeTags
                }
            }
        },
        iam: {
            listRoles: {
                'us-east-1': {
                    data: listRoles
                }
            },
            listAttachedRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listAttachedRolePolicies
                    }
                }
            },
            listRolePolicies: {
                'us-east-1': {
                    [roleName]: {
                        data: listRolePolicies
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    }
                },
            },
            describeTags: {
                'us-east-1': {
                    err: {
                        message: 'error describing tags'
                    }
                }
            }
        },
        iam: {
            listRoles: {
                'us-east-1': {
                    err: {
                        message: 'error listing roles'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': null
            },
            describeTags: {
                'us-east-1': null
            }
        },
        iam: {
            listRoles: {
                'us-east-1': null
            },
            listAttachedRolePolicies: {
                'us-east-1': null
            },
            listRolePolicies: {
                'us-east-1': null
            }
        }
    };
};

describe('webTierInstanceIamRole', function () {
    describe('run', function () {
        it('should PASS if IAM role attached with EC2 instance contains policies', function (done) {
            const cache = createCache([describeInstances[0]], describeTags, [listRoles[0]], listRolePolicies[0], listAttachedRolePolicies[1]);
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if IAM role attached with EC2 instance does not contain policies', function (done) {
            const cache = createCache([describeInstances[0]], describeTags, [listRoles[0]], listRolePolicies[1], listAttachedRolePolicies[1]);
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if instance does not use an IAM role', function (done) {
            const cache = createCache([describeInstances[3]], describeTags, [listRoles[0]], listRolePolicies[0], listAttachedRolePolicies[0]);
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if instance does not have Web-Tier tag key', function (done) {
            const cache = createCache([describeInstances[0]], [describeTags[2]], [listRoles[0]], listRolePolicies[0], listAttachedRolePolicies[0]);
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no EC2 instances found', function (done) {
            const cache = createCache([]);
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no tags found', function (done) {
            const cache = createCache([describeInstances[0]], []);
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe EC2 instances', function (done) {
            const cache = createErrorCache();
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if describe EC2 instances response not found', function (done) {
            const cache = createNullCache();
            webTierInstanceIamRole.run(cache, { ec2_web_tier_tag_key: 'web-tier' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return any results if Web-Tier tag key is not provided in settings', function (done) {
            const cache = createNullCache();
            webTierInstanceIamRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});