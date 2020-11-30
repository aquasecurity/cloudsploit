var expect = require('chai').expect;
const vpcElasticIpLimit = require('./vpcElasticIpLimit');

const describeAccountAttributes = [
    [
        {
            "AttributeName": "max-elastic-ips",
            "AttributeValues": [
                {
                    "AttributeValue": "5"
                }
            ]
        },
    ]
];

const describeAddresses = [
    {
        "PublicIp": "52.73.207.255",
        "AllocationId": "eipalloc-012a1de6c78e459ba",
        "AssociationId": "eipassoc-058f91ade38b552c3",
        "Domain": "vpc",
        "NetworkInterfaceId": "eni-0c9ee96ca599e524f",
        "NetworkInterfaceOwnerId": "111122223333",
        "PrivateIpAddress": "172.31.56.42",
        "PublicIpv4Pool": "amazon",
        "NetworkBorderGroup": "us-east-1"
    }
];

const createCache = (attributes, addresses) => {
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': {
                    data: attributes
                },
            },
            describeAddresses: {
                'us-east-1': {
                    data: addresses
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': {
                    err: {
                        message: 'error describing account attributes'
                    },
                },
            },
            describeAddresses: {
                'us-east-1': {
                    err: {
                        message: 'error describing addresses'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': null,
            },
            describeAddresses: {
                'us-east-1': null,
            },
        },
    };
};


describe('vpcElasticIpLimit', function () {
    describe('run', function () {
        it('should PASS if account is using VPC Elastic IPs less than the defined warn percentage', function (done) {
            const cache = createCache(describeAccountAttributes[0],[describeAddresses[0]]);
            vpcElasticIpLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if account is using VPC Elastic IPs within the defined warn percentage', function (done) {
            const cache = createCache(describeAccountAttributes[0],[describeAddresses[0],describeAddresses[0],describeAddresses[0],describeAddresses[0]]);
            vpcElasticIpLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if account is using VPC Elastic IPs within the defined fail percentage', function (done) {
            const cache = createCache(describeAccountAttributes[0],[describeAddresses[0],describeAddresses[0],describeAddresses[0],describeAddresses[0],describeAddresses[0]]);
            vpcElasticIpLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no addresses found', function (done) {
            const cache = createCache(describeAccountAttributes[0], []);
            vpcElasticIpLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if unable to describe account attributes', function (done) {
            const cache = createErrorCache();
            vpcElasticIpLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should FAIL if unable to describe addresses', function (done) {
            const cache = createCache([]);
            vpcElasticIpLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe account attributes response is not found', function (done) {
            const cache = createNullCache();
            vpcElasticIpLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});