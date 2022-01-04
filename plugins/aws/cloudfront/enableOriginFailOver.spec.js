var expect = require('chai').expect;
const enableOriginFailOver = require('./enableOriginFailOver');

const listDistributions = [
    {
        "Id": "E1A8WDMPAL5GUL",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1A8WDMPAL5GUL",
        "OriginGroups": {
            "Quantity": 1
        },
    },
    {
        "Id": "E2D1TO5LAMVJCU",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E2D1TO5LAMVJCU",
        "OriginGroups": {
            "Quantity": 0
        },
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

describe('enableOriginFailOver', function () {
    describe('run', function () {
        it('should PASS if origin failover is enabled within CloudFront distribution.', function (done) {
            const cache = createCache([listDistributions[0]]);
            enableOriginFailOver.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('origin failover is enabled within CloudFront distribution.');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if origin failover is not enabled within CloudFront distribution.', function (done) {
            const cache = createCache([listDistributions[1]]);
            enableOriginFailOver.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('origin failover is not enabled within CloudFront distribution');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            enableOriginFailOver.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No CloudFront distributions found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            enableOriginFailOver.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for CloudFront distributions');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            enableOriginFailOver.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});