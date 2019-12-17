var expect = require('chai').expect;
var s3Encryption = require('./s3Encryption');

const createCache = (statement) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2008-10-17',
                                Statement: statement ? [statement] : [],
                            }),
                        },
                    },
                },
            },
        },
    };
};

const createCacheNoBucketPolicy = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        err: {
                            code: 'NoSuchBucketPolicy',
                        },
                    },
                },
            },
        },
    };
};

const createCacheErrorListBuckets = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'bad error',
                    },
                },
            },
        },
    };
};

const createCacheNoBuckets = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

describe.only('s3Encryption', function () {
    describe('run', function () {
        it('should FAIL when there are no bucket policy', function (done) {
            const cache = createCacheNoBucketPolicy();
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN when there is an error listing buckets', function (done) {
            const cache = createCacheErrorListBuckets();
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS when there are no buckets', function (done) {
            const cache = createCacheNoBuckets();
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        // todo do error-based bucket policy tests


        it('should PASS when there is a statement that denies insecure requests', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::mybucket/*',
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if explicit deny all with secure condition', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::mybucket/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no deny', function (done) {
            const cache = createCache({
                Effect: 'Allow',
                Principal: '*',
                Action: '*',
                Resource: '*',
            });
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if explicit deny all with secure condition but no * principal', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: { Service: 'ec2.amazonaws.com' },
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::mybucket/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if explicit deny all with secure condition but not on s3:GetObject', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: ['s3:PutObject'],
                Resource: ['arn:aws:s3:::mybucket/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if explicit deny all with secure condition but not on all objects', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::mybucket/mypath/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'false' },
                },
            });
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if explicit deny all with reversed condition', function (done) {
            const cache = createCache({
                Effect: 'Deny',
                Principal: '*',
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::mybucket/*'],
                Condition: {
                    Bool: { 'aws:SecureTransport': 'true' },
                },
            });
            s3Encryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
