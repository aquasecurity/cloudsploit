var expect = require('chai').expect;
const cloudfrontFieldLevelEncryption = require('./cloudfrontFieldLevelEncryption');

const listDistributions = [
    {
        "Id": "EOLX89H5ATF35",
        "ARN": "arn:aws:cloudfront::000011112222:distribution/EOLX89H5ATF35",
        "DefaultCacheBehavior": {
            "FieldLevelEncryptionId": "C3UBCCX0U4WM2I",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6"
        },
    },
    {
        "Id": "EB5R27UN5CRBS",
        "ARN": "arn:aws:cloudfront::000011112222:distribution/EB5R27UN5CRBS",
        "DefaultCacheBehavior": {
            "FieldLevelEncryptionId": "",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6"
        },
    },
];

const createCache = (data, err) => {
    return {
        cloudfront: {
            listDistributions: {
                'us-east-1': {
                    data: data,
                    err: err
                }
            }
        }
    };
};


const createNullCache = () => {
    return {
        cloudfront: {
            listDistributions: {
                'us-east-1': null,
            },
        },
    };
};

describe('cloudfrontFieldLevelEncryption', function () {
    describe('run', function () {
        it('should PASS if distribution has field level encryption enabled', function (done) {
            const cache = createCache([listDistributions[0]]);
            cloudfrontFieldLevelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if distribution does not have field level encryption enabled', function (done) {
            const cache = createCache([listDistributions[1]]);
            cloudfrontFieldLevelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            cloudfrontFieldLevelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            cloudfrontFieldLevelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            cloudfrontFieldLevelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});