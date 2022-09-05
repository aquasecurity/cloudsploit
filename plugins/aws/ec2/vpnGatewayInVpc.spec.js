var expect = require('chai').expect;
const vpnGatewayInVpc = require('./vpnGatewayInVpc');

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


describe('vpnGatewayInVpc', function () {
    describe('run', function () {
        it('should PASS if Virtual Private Gateway is associated with VPC', function (done) {
            const cache = createCache([describeVpnGateways[0]]);
            vpnGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Virtual Private Gateway is associated with VPC')
                done();
            });
        });

        it('should FAIL if Virtual Private Gateway is not associated with VPC', function (done) {
            const cache = createCache([describeVpnGateways[1]]);
            vpnGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Virtual Private Gateway is not associated with VPC')
                done();
            });
        });

        it('should PASS if No Virtual Private Gateways found', function (done) {
            const cache = createCache([]);
            vpnGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Virtual Private Gateways found')
                done();
            });
        });

        it('should UNKNOWN if unable to describe Virtual Private Gateways', function (done) {
            const cache = createErrorCache();
            vpnGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Virtual Private Gateways')
                done();
            });
        });

        it('should not return anything if describe Virtual Private Gateways response not found', function (done) {
            const cache = createNullCache();
            vpnGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
