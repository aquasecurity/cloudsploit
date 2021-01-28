var expect = require('chai').expect;
const vpcSubnetInstancesPresent = require('./vpcSubnetInstancesPresent');

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
                "LaunchTime": "2020-12-05T18:35:50+00:00",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {},
                "PrivateDnsName": "ip-172-31-28-46.ec2.internal",
                "PrivateIpAddress": "172.31.28.46",
                "ProductCodes": [],
                "PublicDnsName": "ec2-18-209-19-81.compute-1.amazonaws.com",
                "PublicIpAddress": "18.209.19.81",
                "State": {},
                "StateTransitionReason": "",
                "SubnetId": "subnet-aac6b3e7",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
                "NetworkInterfaces": [],
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [],
                "SourceDestCheck": true,
                "Tags": [],
                "VirtualizationType": "hvm",
                "CpuOptions": {},
                "CapacityReservationSpecification": {},
                "HibernationOptions": {},
                "MetadataOptions": {},
                "EnclaveOptions": {}
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-087ce52925d75c272"
    },
];

const describeSubnets = [
    {
        "AvailabilityZone": "us-east-1d",
        "AvailabilityZoneId": "use1-az6",
        "AvailableIpAddressCount": 250,
        "CidrBlock": "172.16.0.0/24",
        "DefaultForAz": false,
        "MapPublicIpOnLaunch": false,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-aac6b3e7",
        "VpcId": "vpc-036273a23dcdba22f",
        "OwnerId": "111122223333",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "Tags": [
            {
                "Key": "AWSServiceAccount",
                "Value": "697148468905"
            }
        ],
        "SubnetArn": "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-027b3e2dbd13be412"
    },
    {
        "AvailabilityZone": "us-east-1d",
        "AvailabilityZoneId": "use1-az6",
        "AvailableIpAddressCount": 250,
        "CidrBlock": "172.16.0.0/24",
        "DefaultForAz": false,
        "MapPublicIpOnLaunch": false,
        "MapCustomerOwnedIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-027b3e2dbd13be412",
        "VpcId": "vpc-036273a23dcdba22f",
        "OwnerId": "111122223333",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "Tags": [
            {
                "Key": "AWSServiceAccount",
                "Value": "697148468905"
            }
        ],
        "SubnetArn": "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-027b3e2dbd13be412"
    }
];


const createCache = (instances, subnets) => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
            describeSubnets: {
                'us-east-1': {
                    data: subnets
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            },
            describeSubnets: {
                'us-east-1': {
                    err: {
                        message: 'error describing VPC subnets'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': null,
            },
            describeSubnets: {
                'us-east-1': null,
            },
        },
    };
};

describe('vpcSubnetInstancesPresent', function () {
    describe('run', function () {
        it('should PASS if subnet has instances attached', function (done) {
            const cache = createCache([describeInstances[0]], [describeSubnets[0]]);
            vpcSubnetInstancesPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if subnet does not have any instance attached', function (done) {
            const cache = createCache([describeInstances[0]], [describeSubnets[1]]);
            vpcSubnetInstancesPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPC subnets found', function (done) {
            const cache = createCache([], []);
            vpcSubnetInstancesPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for instances', function (done) {
            const cache = createErrorCache();
            vpcSubnetInstancesPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to query for VPC subnets', function (done) {
            const cache = createCache([]);
            vpcSubnetInstancesPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe subnets response not found', function (done) {
            const cache = createNullCache();
            vpcSubnetInstancesPresent.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
