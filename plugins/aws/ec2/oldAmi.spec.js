var expect = require('chai').expect;
const oldAmi = require('./oldAmi');

const describeImages = [
    {
        ImageId: 'ami-046b09f5340dfd8gb',
        CreationDate: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString() // 100 days old
    },
    {
        ImageId: 'ami-046b09f5340dfd8gc',
        CreationDate: new Date(Date.now() - 70 * 24 * 60 * 60 * 1000).toISOString() // 70 days old
    },
    {
        ImageId: 'ami-046b09f5340dfd8gd',
        CreationDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days old
    },
    {
        ImageId: 'ami-046b09f5340dfd8ge',
        // No CreationDate
    }
];

const createCache = (images) => {
    return {
        ec2: {
            describeImages: {
                'us-east-1': {
                    data: images
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeImages: {
                'us-east-1': {
                    err: {
                        message: 'error describing AMIs'
                    }
                },
            },
        },
    };
};

describe('oldAmi', function () {
    describe('run', function () {
        
        it('should return UNKNOWN if unable to query for AMIs', function (done) {
            const cache = createErrorCache();
            oldAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for AMIs');
                done();
            });
        });

        it('should return PASS if no AMIs found', function (done) {
            const cache = createCache([]);
            oldAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No AMIs found');
                done();
            });
        });

        it('should return FAIL if AMI is older than fail threshold (90 days)', function (done) {
            const cache = createCache([describeImages[0]]);
            oldAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('100 days old');
                done();
            });
        });

        it('should return PASS if AMI is newer than warn threshold', function (done) {
            const cache = createCache([describeImages[2]]);
            oldAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('30 days old');
                done();
            });
        });

        it('should return UNKNOWN if AMI does not have a creation date', function (done) {
            const cache = createCache([describeImages[3]]);
            oldAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('AMI does not have a creation date');
                done();
            });
        });
    });
});

