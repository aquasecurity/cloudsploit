var expect = require('chai').expect;
const excessiveSecurityGroups = require('./excessiveSecurityGroups');

const describeSecurityGroups = [
    {
        Description: 'default VPC security group',
        GroupName: 'default',
        IpPermissions: [Array],
        OwnerId: '111122223333',
        GroupId: 'sg-aa941691',
        IpPermissionsEgress: [Array],
        Tags: [],
        VpcId: 'vpc-99de2fe4'
    }
];

const createCache = (groups) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    data: groups
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing security groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': null,
            },
        },
    };
};


describe('excessiveSecurityGroups', function () {
    describe('run', function () {
        it('should PASS if acceptable number of security groups present', function (done) {
            const cache = createCache([describeSecurityGroups[0]]);
            var settings = {
                excessive_security_groups_fail: 2,
                excessive_security_groups_warn: 1
            };
            excessiveSecurityGroups.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if large number of security groups present', function (done) {
            const cache = createCache([describeSecurityGroups[0],describeSecurityGroups[0]]);
            var settings = {
                excessive_security_groups_fail: 2,
                excessive_security_groups_warn: 1
            };
            excessiveSecurityGroups.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if excessive number of security groups present', function (done) {
            const cache = createCache([describeSecurityGroups[0],describeSecurityGroups[0],describeSecurityGroups[0]]);
            var settings = {
                excessive_security_groups_fail: 2,
                excessive_security_groups_warn: 1
            };
            excessiveSecurityGroups.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no security groups present', function (done) {
            const cache = createCache([]);
            excessiveSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe security groups', function (done) {
            const cache = createErrorCache();
            excessiveSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            excessiveSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
