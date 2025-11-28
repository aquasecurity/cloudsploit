var expect = require('chai').expect;
const amiNamingConvention = require('./amiNamingConvention');

const describeImages = [
    {
        ImageId: 'ami-046b09f5340dfd8gb',
        Tags: [
            { Key: 'Name', Value: 'ami-ue1-p-nodejs' }
        ]
    },
    {
        ImageId: 'ami-046b09f5340dfd8gc',
        Tags: [
            { Key: 'Name', Value: 'ami-uw2-d-apache-spark' }
        ]
    },
    {
        ImageId: 'ami-046b09f5340dfd8gd',
        Tags: [
            { Key: 'Name', Value: 'MyCustomAMI' }
        ]
    },
    {
        ImageId: 'ami-046b09f5340dfd8ge',
        Tags: [
            { Key: 'Environment', Value: 'Production' }
        ]
    },
    {
        ImageId: 'ami-046b09f5340dfd8gf',
        Tags: []
    }
];

const createCache = (instances) => {
    return {
        ec2: {
            describeImages: {
                'us-east-1': {
                    data: instances
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


describe('amiNamingConvention', function () {
    describe('run', function () {
        
        it('should return UNKNOWN if unable to query for AMIs', function (done) {
            const cache = createErrorCache();
            amiNamingConvention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for AMIs');
                done();
            });
        });

        it('should return PASS if no AMIs found', function (done) {
            const cache = createCache([]);
            amiNamingConvention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No AMIs found');
                done();
            });
        });

        it('should return PASS if AMI Name tag follows naming convention', function (done) {
            const cache = createCache([describeImages[0]]);
            amiNamingConvention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('follows organizational naming convention');
                done();
            });
        });

        it('should return FAIL if AMI Name tag does not follow naming convention', function (done) {
            const cache = createCache([describeImages[2]]);
            amiNamingConvention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('does not follow organizational naming convention');
                done();
            });
        });

        it('should return FAIL if AMI does not have a Name tag', function (done) {
            const cache = createCache([describeImages[3]]);
            amiNamingConvention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('AMI does not have a Name tag');
                done();
            });
        });

        it('should return FAIL if AMI has empty tags array', function (done) {
            const cache = createCache([describeImages[4]]);
            amiNamingConvention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('AMI does not have a Name tag');
                done();
            });
        });
    });
});

