var assert = require('assert');
var expect = require('chai').expect;
var ec2MetadataOptions = require('./ec2MetadataOptions')

const createCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: [{
                        Instances: instances
                    }],
                },
            },
        },
    };
};

const createEmptyCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'bad error'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInstances: null,
        },
    };
};

describe('ec2MetadataOptions', function () {
    describe('run', function () {
        it('should PASS if there are no instances', function (done) {
            const cache = createCache([]);
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no reservations', function (done) {
            const cache = createEmptyCache();
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if IMDSv1 is used', function (done) {
            const cache = createCache([{
                MetadataOptions: {
                    HttpTokens: 'optional',
                    HttpEndpoint: 'enabled',
                },
            }]);
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if MetadataOptions are not found', function (done) {
            const cache = createCache([{}]);
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if describeInstances error', function (done) {
            const cache = createErrorCache();
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should do nothing if describeInstances is null', function (done) {
            const cache = createNullCache();
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should PASS if IMDSv2 is used - tokens required', function (done) {
            const cache = createCache([{
                MetadataOptions: {
                    HttpTokens: 'required',
                    HttpEndpoint: 'enabled',
                },
            }]);
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if IMDSv2 is used - endpoint disabled', function (done) {
            const cache = createCache([{
                MetadataOptions: {
                    HttpEndpoint: 'disabled',
                },
            }]);
            ec2MetadataOptions.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
