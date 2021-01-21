var expect = require('chai').expect;
const unusedVGW = require('./unusedVirtualPrivateGateway');

const describeVpnGateways = [
    {
        "State": "available",
        "Type": "ipsec.1",
        "VpcAttachments": [
            {
                "State": "attached",
                "VpcId": "vpc-99de2fe4"
            }
        ],
        "VpnGatewayId": "vgw-049df54387fd42105",
        "AmazonSideAsn": 64512,
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-69"
            }
        ]
    },
    {
        "State": "available",
        "Type": "ipsec.1",
        "VpcAttachments": [
            {
                "State": "detached",
                "VpcId": "vpc-99de2fe4"
            }
        ],
        "VpnGatewayId": "vgw-049df54387fd42105",
        "AmazonSideAsn": 64512,
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-69"
            }
        ]
    },
    {
        "State": "available",
        "Type": "ipsec.1",
        "VpcAttachments": [],
        "VpnGatewayId": "vgw-049df54387fd42105",
        "AmazonSideAsn": 64512,
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-69"
            }
        ]
    }
];

const createCache = (describeVpnGateways) => {
    return {
        ec2: {
            describeVpnGateways: {
                'us-east-1': {
                    data: describeVpnGateways
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVpnGateways: {
                'us-east-1': {
                    err: {
                        message: 'error describing Virtual Private Gateways'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVpnGateways: {
                'us-east-1': null,
            },
        },
    };
};


describe('unusedVGW', function () {
    describe('run', function () {
        it('should PASS if Virtual Private Gateway is in use', function (done) {
            const cache = createCache([describeVpnGateways[0]]);
            unusedVGW.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Virtual Private Gateway is not in use', function (done) {
            const cache = createCache([describeVpnGateways[1]]);
            unusedVGW.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Virtual Private Gateway does not have any VPC attachment', function (done) {
            const cache = createCache([describeVpnGateways[2]]);
            unusedVGW.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No Virtual Private Gateways found', function (done) {
            const cache = createCache([]);
            unusedVGW.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Virtual Private Gateways', function (done) {
            const cache = createErrorCache();
            unusedVGW.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe Virtual Private Gateways response not found', function (done) {
            const cache = createNullCache();
            unusedVGW.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
