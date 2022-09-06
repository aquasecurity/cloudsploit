var expect = require('chai').expect;
const internetGatewayInVpc = require('./internetGatewayInVpc');

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


const createCache = (ig) => {
    return {
        ec2: {
            describeInternetGateways: {
                'us-east-1': {
                    data: ig
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
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInternetGateways: {
                'us-east-1': null,
            },
        },
    };
};

describe('internetGatewayInVpc', function () {
    describe('run', function () {
        it('should PASS if Internet Gateway is associated with VPC', function (done) {
            const cache = createCache([describeInternetGateways[0]]);
            internetGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Internet Gateway is associated with VPC')
                done();
            });
        });

        it('should FAIL if Internet Gateway is not associated with VPC', function (done) {
            const cache = createCache([describeInternetGateways[1]]);
            internetGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Internet Gateway is not associated with VPC')
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Internet Gateways', function (done) {
            const cache = createErrorCache();
            internetGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Internet Gateways')
                done();
            });
        });

        it('should PASS if no Internet Gateways found', function (done) {
            const cache = createCache([]);
            internetGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Internet Gateways found')
                done();
            });
        });

        it('should not return anything if describe internet gateways response is not found', function (done) {
            const cache = createNullCache();
            internetGatewayInVpc.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});