var expect = require('chai').expect;
var accountPublicAccessBlock = require('./accountPublicAccessBlock');

const createCache = (data) => {
    return {
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '1'
                },
            }
        },
        s3control: {
            getPublicAccessBlock: {
                'us-east-1': {
                    '1': data,
                },
            }
        }
    };
};


describe('accountPublicAccessBlock', function () {
    describe('run', function () {
        it('should PASS if public access block is fully configured', function (done) {
            var data = {
                data: {
                    PublicAccessBlockConfiguration: {
                        BlockPublicAcls: true,
                        IgnorePublicAcls: true,
                        BlockPublicPolicy: true,
                        RestrictPublicBuckets: true,
                    },
                }
            }
            const cache = createCache(data);
            accountPublicAccessBlock.run(cache, {s3_public_access_block_on_account: true}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should Fail if public access block is not fully configured', function (done) {
            var data = {
                data: {
                    PublicAccessBlockConfiguration: {
                        BlockPublicAcls: true,
                        IgnorePublicAcls: true,
                        BlockPublicPolicy: false,
                        RestrictPublicBuckets: true,
                    },
                }
            }
            const cache = createCache(data);
            accountPublicAccessBlock.run(cache, {s3_public_access_block_on_account: true}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should Fail if there is an access block error', function (done) {
            var data = {
                err: {code: 'NoSuchPublicAccessBlockConfiguration'}
            }
            const cache = createCache(data);
            accountPublicAccessBlock.run(cache, {s3_public_access_block_on_account: true}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should Fail if there is no data', function (done) {
            var data = {
                data: null
            }
            const cache = createCache(data);
            accountPublicAccessBlock.run(cache, {s3_public_access_block_on_account: true}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
    });
});