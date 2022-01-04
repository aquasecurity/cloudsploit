var expect = require('chai').expect;
const compressObjectsAutomatically = require('./compressObjectsAutomatically');

const listDistributions = [
    {
        "Id": "E1A8WDMPAL5GUL",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1A8WDMPAL5GUL",
        "DefaultCacheBehavior": {
            "Compress": true
        }
    },
    {
        "Id": "E2D1TO5LAMVJCU",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E2D1TO5LAMVJCU",
        "DefaultCacheBehavior": {
            "Compress": false
        }
    }
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

describe('compressObjectsAutomatically', function () {
    describe('run', function () {
        it('should PASS if Cloudfront web distribution is currently configured to compress files (objects) automatically', function (done) {
            const cache = createCache([listDistributions[0]]);
            compressObjectsAutomatically.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Cloudfront web distribution is currently configured to compress files (objects) automatically.', function (done) {
            const cache = createCache([listDistributions[1]]);
            compressObjectsAutomatically.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            compressObjectsAutomatically.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            compressObjectsAutomatically.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            compressObjectsAutomatically.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});