var expect = require('chai').expect;
const cloudfrontInUse = require('./cloudfrontInUse');

const listDistributions = [
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "WebACLId": "ca44237b-b1d8-46b2-abad-ada48c7f0894",
    },
    {}
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

describe('cloudfrontInUse', function () {
    describe('run', function () {
        it('should PASS if AWS CloudFront service is in use', function (done) {
            const cache = createCache([listDistributions[0]]);
            cloudfrontInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('CloudFront service is in use')
                done();
            });
        });

        it('should FAIL if CloudFront service is not in use', function (done) {
            const cache = createCache(listDistributions[1]);
            cloudfrontInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('CloudFront service is not in use')
                done();
            });
        });


        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache(null, { message: 'Unable to list distributions' });
            cloudfrontInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('Unable to list distributions')
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            cloudfrontInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});