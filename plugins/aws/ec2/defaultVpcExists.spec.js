var expect = require('chai').expect;
var defaultVpcExists = require('./defaultVpcExists')

const createCache = (vpcs) => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    data: vpcs,
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
                        message: 'error describing vpcs'
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
        },
    };
};

describe('defaultVpcExists', function () {
    describe('run', function () {
        it('should FAIL if a default vpc is detected', function (done) {
            const cache = createCache([{ IsDefault: false }, { IsDefault: true }]);
            defaultVpcExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no default vpc is detected', function (done) {
            const cache = createCache([{ IsDefault: false }, { IsDefault: false }]);
            defaultVpcExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no vpcs are detected', function (done) {
            const cache = createCache([]);
            defaultVpcExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for VPCs', function (done) {
            const cache = createErrorCache();
            defaultVpcExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for VPCs', function (done) {
            const cache = createNullCache();
            defaultVpcExists.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
