var expect = require('chai').expect;
const multipleSubnets = require('./multipleSubnets');

const describeVpcs = [
    {
        "CidrBlock": "172.31.0.0/16",
        "DhcpOptionsId": "dopt-3a821040",
        "State": "available",
        "VpcId": "vpc-99de2fe4",
        "OwnerId": "111122223333",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [
            {
                "AssociationId": "vpc-cidr-assoc-35ef2d5a",
                "CidrBlock": "172.31.0.0/16",
                "CidrBlockState": {
                    "State": "associated"
                }
            }
        ],
        "IsDefault": true
    },
    {
        "CidrBlock": "172.31.0.0/16",
        "DhcpOptionsId": "dopt-3a821040",
        "State": "available",
        "OwnerId": "111122223333",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [
            {
                "AssociationId": "vpc-cidr-assoc-35ef2d5a",
                "CidrBlock": "172.31.0.0/16",
                "CidrBlockState": {
                    "State": "associated"
                }
            }
        ],
        "IsDefault": true
    }
];

const describeSubnets = [
    {
        "Subnets": [
            {
                "AvailabilityZone": "us-east-1b",
                "AvailabilityZoneId": "use1-az4",
                "AvailableIpAddressCount": 4088,
                "CidrBlock": "172.31.16.0/20",
                "DefaultForAz": true,
                "MapPublicIpOnLaunch": true,
                "MapCustomerOwnedIpOnLaunch": false,
                "State": "available",
                "SubnetId": "subnet-aac6b3e7",
                "VpcId": "vpc-99de2fe4",
                "OwnerId": "111122223333",
                "AssignIpv6AddressOnCreation": false,
                "Ipv6CidrBlockAssociationSet": [],
                "SubnetArn": "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-aac6b3e7"
            },
            {
                "AvailabilityZone": "us-east-1c",
                "AvailabilityZoneId": "use1-az4",
                "AvailableIpAddressCount": 4088,
                "CidrBlock": "172.31.16.0/20",
                "DefaultForAz": true,
                "MapPublicIpOnLaunch": true,
                "MapCustomerOwnedIpOnLaunch": false,
                "State": "available",
                "SubnetId": "subnet-aac6b3e7",
                "VpcId": "vpc-99de2fe4",
                "OwnerId": "111122223333",
                "AssignIpv6AddressOnCreation": false,
                "Ipv6CidrBlockAssociationSet": [],
                "SubnetArn": "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-aac6b3e7"
            },
        ]
    },
    {
        "Subnets": [
            {
                "AvailabilityZone": "us-east-1b",
                "AvailabilityZoneId": "use1-az4",
                "AvailableIpAddressCount": 4088,
                "CidrBlock": "172.31.16.0/20",
                "DefaultForAz": true,
                "MapPublicIpOnLaunch": true,
                "MapCustomerOwnedIpOnLaunch": false,
                "State": "available",
                "SubnetId": "subnet-aac6b3e7",
                "VpcId": "vpc-99de2fe4",
                "OwnerId": "111122223333",
                "AssignIpv6AddressOnCreation": false,
                "Ipv6CidrBlockAssociationSet": [],
                "SubnetArn": "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-aac6b3e7"
            },
        ]
    },
    {
        "Subnets": []
    }
];


const createCache = (vpcs, subnets) => {
    if (vpcs && vpcs.length && vpcs[0].VpcId) var vpcId = vpcs[0].VpcId;
    return {
        ec2:{
            describeVpcs: {
                'us-east-1': {
                    data: vpcs
                },
            },
            describeSubnets: {
                'us-east-1': {
                    [vpcId]: {
                        data: subnets
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeVpcs: {
                'us-east-1': {
                    err: {
                        message: 'error describing vpcs'
                    },
                },
            },
            describeSubnets: {
                'us-east-1': {
                    err: {
                        message: 'error describing subnets'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeVpcs: {
                'us-east-1': null,
            },
            describeSubnets: {
                'us-east-1': null,
            },
        },
    };
};


describe('multipleSubnets', function () {
    describe('run', function () {
        it('should PASS if multiple subnets used in one VPC', function (done) {
            const cache = createCache([describeVpcs[0]],describeSubnets[0]);
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if only one subnets in one VPC is used', function (done) {
            const cache = createCache([describeVpcs[0]],describeSubnets[1]);
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if the VPC does not contain any subnets', function (done) {
            const cache = createCache([describeVpcs[0]],describeSubnets[2]);
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no VPCs found', function (done) {
            const cache = createCache([]);
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if multiple VPCs are used', function (done) {
            const cache = createCache([describeVpcs[0],describeVpcs[0]]);
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON if vpcId is not found', function (done) {
            const cache = createCache([describeVpcs[1]]);
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNWON if unable to describe VPCs', function (done) {
            const cache = createErrorCache();
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe subnets', function (done) {
            const cache = createCache([describeVpcs[0]]);
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe VPCs response not found', function (done) {
            const cache = createNullCache();
            multipleSubnets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
