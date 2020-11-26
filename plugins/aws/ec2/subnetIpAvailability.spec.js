var expect = require('chai').expect;
const subnetIpAvailability = require('./subnetIpAvailability');

const describeSubnets = [
    {
        "AvailabilityZone": "us-east-1b",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 1500,
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
        "AvailabilityZone": "us-east-1b",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 1000,
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
        "AvailabilityZone": "us-east-1b",
        "AvailabilityZoneId": "use1-az4",
        "AvailableIpAddressCount": 200,
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
];


const createCache = (subnets) => {
    return {
        ec2:{
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
            describeSubnets: {
                'us-east-1': {
                    err: {
                        message: 'error describing subnets'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSubnets: {
                'us-east-1': null,
            },
        },
    };
};

describe('subnetIpAvailability', function () {
    describe('run', function () {
        it('should PASS if subnet is using IPs less than the defined warn percentage', function (done) {
            const cache = createCache([describeSubnets[0]]);
            subnetIpAvailability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if subnet is using IPs within the defined warn percentage', function (done) {
            const cache = createCache([describeSubnets[1]]);
            subnetIpAvailability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL subnet is using IPs more than the defined fail percentage', function (done) {
            const cache = createCache([describeSubnets[2]]);
            subnetIpAvailability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no subnets found', function (done) {
            const cache = createCache([]);
            subnetIpAvailability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe subnets', function (done) {
            const cache = createErrorCache();
            subnetIpAvailability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe subnets response not found', function (done) {
            const cache = createNullCache();
            subnetIpAvailability.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
