var expect = require('chai').expect;
const unassociatedElasticIp = require('./unassociatedElasticIp');

const describeAddresses = [
    {
        "InstanceId": "i-03afb9daa31f31bb0",
        "PublicIp": "18.235.251.59",
        "AllocationId": "eipalloc-00806f12608a4e3ca",
        "AssociationId": "eipassoc-03c6b0f3a49c40072",
        "Domain": "vpc",
        "NetworkInterfaceId": "eni-0a53de7b449ed51e0",
        "NetworkInterfaceOwnerId": "111122223333",
        "PrivateIpAddress": "172.31.54.187",
        "PublicIpv4Pool": "amazon",
        "NetworkBorderGroup": "us-east-1"
    },
    {
        "PublicIp": "18.235.251.59",
        "AllocationId": "eipalloc-00806f12608a4e3ca",
        "Domain": "vpc",
        "PublicIpv4Pool": "amazon",
        "NetworkBorderGroup": "us-east-1"
    }
]

const createCache = (addresses) => {
    return {
        ec2: {
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
        ec2: {
            describeAddresses: {
                'us-east-1': {
                    err: {
                        message: 'error describing ec2 instances'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeAddresses: {
                'us-east-1': null,
            },
        },
    };
};

describe('unassociatedElasticIp', function () {
    describe('run', function () {
        it('should PASS if Elastic IP address is associated to a resource', function (done) {
            const cache = createCache([describeAddresses[0]]);
            unassociatedElasticIp.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Elastic IP address is not associated to any resource', function (done) {
            const cache = createCache([describeAddresses[1]]);
            unassociatedElasticIp.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Elastic IP address found', function (done) {
            const cache = createCache([]);
            unassociatedElasticIp.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if unable to fetch Elastic IP addresses', function (done) {
            const cache = createNullCache();
            unassociatedElasticIp.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error describing Elastic IP addresses', function (done) {
            const cache = createErrorCache();
            unassociatedElasticIp.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});