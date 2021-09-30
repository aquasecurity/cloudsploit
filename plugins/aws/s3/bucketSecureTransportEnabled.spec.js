var expect = require('chai').expect;
const bucketSecureTransportEnabled = require('./bucketSecureTransportEnabled');

const listBuckets = [
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z'
    },
    {
        Name: 'elasticbeanstalk-us-east-1-123456654321',
        CreationDate: '2020-08-20T17:42:52.000Z'
    },
    {
      Name: 'test-bucket-sploit-100',
      CreationDate: '2020-09-06T09:44:16.000Z'
    }
];

const getBucketPolicy = [
    {
        Policy: '{"Version":"2012-10-17","Id":"ExamplePolicy","Statement":[{"Sid":"","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::00000011111:root"},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::staging-01-sd-logs/*"]},{"Sid":"","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::staging-01-sd-logs/*","arn:aws:s3:::staging-01-sd-logs"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
    },
    {
        Policy: '{"Version":"2008-10-17","Statement":[{"Sid":"Stmt1537431944913","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::00001111122:root"},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::alqemy-upwork/*"]},{"Sid":"Stmt1537431944211","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::alqemy-upwork/*","arn:aws:s3:::alqemy-upwork"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Id":"ExamplePolicy","Statement":[]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Id":"ExamplePolicy","Statement":[{"Sid":"","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::00000011111:root"},"Action":["s3:PutObject"],"Resource":["arn:aws:s3:::staging-01-sd-logs/*"]},{"Sid":"","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::staging-01-sd-logs/*","arn:aws:s3:::staging-01-sd-logs"],"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}'
    },
];


const createCache = (listBuckets, getBucketPolicy) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: listBuckets
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    [listBuckets[0].Name]: {
                        data: getBucketPolicy
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    [listBuckets[0].Name]: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'error while listing buckets'
                    },
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket policy'
                    },
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null,
            },
            getBucketPolicy: {
                'us-east-1': null,
            },
        },
    };
};


describe('bucketSecureTransportEnabled', function () {
    describe('run', function () {
        it('should PASS if S3 bucket enforces SSL to secure data in transit', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[0]);
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket policy does not include any statement', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[2]);
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket does not enforce SSL to secure data in transit', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[3]);
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if error while listing S3 buckets', function (done) {
            const cache = createErrorCache();
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if S3 list bucket response is not found', function (done) {
            const cache = createNullCache();
            bucketSecureTransportEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});