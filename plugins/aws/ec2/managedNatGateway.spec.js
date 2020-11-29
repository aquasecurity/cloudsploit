var expect = require('chai').expect;
const managedNatGateway = require('./managedNatGateway');

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
        "CidrBlock": "10.0.0.0/24",
        "DhcpOptionsId": "dopt-3a821040",
        "State": "available",
        "VpcId": "vpc-0b739af479bea9bff",
        "OwnerId": "111122223333",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [
            {
                "AssociationId": "vpc-cidr-assoc-017f349579cad8c30",
                "CidrBlock": "10.0.0.0/24",
                "CidrBlockState": {
                    "State": "associated"
                }
            }
        ],
        "IsDefault": false,
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-vpc"
            }
        ]
    }
]

const describeNatGateways = [
    {
        "CreateTime": "2020-10-22T03:52:03.000Z",
        "NatGatewayAddresses": [
            {
                "AllocationId": "eipalloc-012a1de6c78e459ba",
                "NetworkInterfaceId": "eni-0e1f6ede5831b878c",
                "PrivateIp": "172.31.50.47",
                "PublicIp": "52.73.207.255"
            }
        ],
        "NatGatewayId": "nat-042a6ab635c627c61",
        "State": "available",
        "SubnetId": "subnet-6a8b635b",
        "VpcId": "vpc-99de2fe4",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-65"
            }
        ]
    }
];


const createCache = (vpc, nat) => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    data: vpc
                },
            },
            describeNatGateways: {
                'us-east-1': {
                    data: nat
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    err: {
                        message: 'error describing VPCs'
                    },
                },
            },
            describeNatGateways: {
                'us-east-1': {
                    err: {
                        message: 'error describing NAT Gateways'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': null,
            },
            describeNatGateways: {
                'us-east-1': null,
            },
        },
    };
};


describe('managedNatGateway', function () {
    describe('run', function () {
        it('should PASS if VPC is using managed NAT gateway', function (done) {
            const cache = createCache([describeVpcs[0]], [describeNatGateways[0]]);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if VPC is not using managed NAT gateway', function (done) {
            const cache = createCache([describeVpcs[1]], [describeNatGateways[0]]);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPCs found', function (done) {
            const cache = createCache([]);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe VPCs', function (done) {
            const cache = createErrorCache();
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return anything if describe VPCs response not found', function (done) {
            const cache = createNullCache();
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});