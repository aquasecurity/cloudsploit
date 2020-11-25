var expect = require('chai').expect;
const natMultiAz = require('./natMultiAz');

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
    }
];

const describeNatGateways = [
    {
        "CreateTime": "2020-11-12T19:59:52.000Z",
        "NatGatewayAddresses": [
            {
                "AllocationId": "eipalloc-02fbee66ba40a5920",
                "NetworkInterfaceId": "eni-06bb49bfd636abb8e",
                "PrivateIp": "172.31.60.19"
            }
        ],
        "NatGatewayId": "nat-07895bffa88a7af7c",
        "State": "pending",
        "SubnetId": "subnet-6a8b635b",
        "VpcId": "vpc-99de2fe4",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-spec"
            }
        ]
    },
    {
        "CreateTime": "2020-11-12T19:59:52.000Z",
        "NatGatewayAddresses": [
            {
                "AllocationId": "eipalloc-02fbee66ba40a5920",
                "NetworkInterfaceId": "eni-06bb49bfd636abb8e",
                "PrivateIp": "172.31.60.19"
            }
        ],
        "NatGatewayId": "nat-07895bffa88a7af7c",
        "State": "pending",
        "SubnetId": "subnet-6a8b635c",
        "VpcId": "vpc-99de2fe4",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-spec"
            }
        ]
    },
];


const createCache = (vpcs, natGateways) => {
    return {
        ec2:{
            describeVpcs: {
                'us-east-1': {
                    data: vpcs
                },
            },
            describeNatGateways: {
                'us-east-1': {
                    data: natGateways
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
            describeNatGateways: {
                'us-east-1': {
                    err: {
                        message: 'error describing NAT gateways'
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
            describeNatGateways: {
                'us-east-1': null,
            },
        },
    };
};


describe('natMultiAz', function () {
    describe('run', function () {
        it('should PASS if VPC is using NAT gateways in multiple subnet', function (done) {
            const cache = createCache([describeVpcs[0]],[describeNatGateways[0],describeNatGateways[1]]);
            natMultiAz.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if VPC is using NAT gateways in only 1 subnet', function (done) {
            const cache = createCache([describeVpcs[0]],[describeNatGateways[0]]);
            natMultiAz.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no VPC with NAT gateways found', function (done) {
            const cache = createCache([describeVpcs[0]],[]);
            natMultiAz.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no VPCs found', function (done) {
            const cache = createCache([]);
            natMultiAz.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON if unable to describe VPCs', function (done) {
            const cache = createErrorCache();
            natMultiAz.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe NAT gateways', function (done) {
            const cache = createCache([describeVpcs[0]]);
            natMultiAz.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe VPCs response not found', function (done) {
            const cache = createNullCache();
            natMultiAz.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
