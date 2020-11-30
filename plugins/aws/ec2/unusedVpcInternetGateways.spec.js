var expect = require('chai').expect;
const unusedVpcInternetGateways = require('./unusedVpcInternetGateways');

const describeInternetGateways = [
    {
        "Attachments": [
            {
                "State": "available",
                "VpcId": "vpc-99de2fe4"
            }
        ],
        "InternetGatewayId": "igw-7f3e1a04",
        "OwnerId": "111122223333",
        "Tags": []
    },
    {
        "Attachments": [],
        "InternetGatewayId": "igw-0a82fd444d2c310d1",
        "OwnerId": "111122223333",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-64"
            }
        ]
    }
];

const describeEgressOnlyInternetGateways = [
    {
        "Attachments": [
            {
                "State": "attached",
                "VpcId": "vpc-99de2fe4"
            }
        ],
        "EgressOnlyInternetGatewayId": "eigw-05eff80eabd1ea8e0",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-64-egress"
            }
        ]
    },
    {
        "Attachments": [],
        "EgressOnlyInternetGatewayId": "eigw-05eff80eabd1ea8e0",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-64-egress"
            }
        ]
    }
];


const createCache = (ig, eig) => {
    return {
        ec2: {
            describeInternetGateways: {
                'us-east-1': {
                    data: ig
                },
            },
            describeEgressOnlyInternetGateways: {
                'us-east-1': {
                    data: eig
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeInternetGateways: {
                'us-east-1': {
                    err: {
                        message: 'error describing Internet Gateways'
                    },
                },
            },
            describeEgressOnlyInternetGateways: {
                'us-east-1': {
                    err: {
                        message: 'error describing Egress-Only Internet Gateways'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInternetGateways: {
                'us-east-1': null,
            },
            describeEgressOnlyInternetGateways: {
                'us-east-1': null,
            },
        },
    };
};

describe('unusedVpcInternetGateways', function () {
    describe('run', function () {
        it('should PASS if Internet Gateway is in use', function (done) {
            const cache = createCache([describeInternetGateways[0]], [describeEgressOnlyInternetGateways[0]]);
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Egress-Only Internet Gateway is in use', function (done) {
            const cache = createCache([describeInternetGateways[0]], [describeEgressOnlyInternetGateways[0]]);
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Internet Gateway is not in use', function (done) {
            const cache = createCache([describeInternetGateways[1]], [describeEgressOnlyInternetGateways[0]]);
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Egress-Only Internet Gateway is not in use', function (done) {
            const cache = createCache([describeInternetGateways[1]], [describeEgressOnlyInternetGateways[1]]);
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Internet Gateway', function (done) {
            const cache = createErrorCache();
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Egress-Only Internet Gateway', function (done) {
            const cache = createErrorCache();
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no Internet Gateways found', function (done) {
            const cache = createCache([]);
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no Egress-Only Internet Gateways found', function (done) {
            const cache = createCache([], []);
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should not return anything if describe internet gateways response is not found', function (done) {
            const cache = createNullCache();
            unusedVpcInternetGateways.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});