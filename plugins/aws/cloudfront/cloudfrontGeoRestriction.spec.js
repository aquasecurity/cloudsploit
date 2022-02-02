var expect = require('chai').expect;
const cloudfrontGeoRestriction = require('./cloudfrontGeoRestriction');

const listDistributions = [
    {
        "Id": "E1A8WDMPAL5GUL",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1A8WDMPAL5GUL",
        "Restrictions": {
            "GeoRestriction": {
                "RestrictionType": "whitelist",
                "Quantity": 1,
                "Items": [
                    "AR"
                ]
            }
        },
    },
    {
        "Id": "E2D1TO5LAMVJCU",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E2D1TO5LAMVJCU",
        "Restrictions": {
            "GeoRestriction": {
                "RestrictionType": "none",
                "Quantity": 1,
                "Items": [
                    "AR"
                ]
            }
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

describe('cloudfrontGeoRestriction', function () {
    describe('run', function () {
        it('should PASS if geo restriction is enabled within CloudFront distribution.', function (done) {
            const cache = createCache([listDistributions[0]]);
            cloudfrontGeoRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Geo restriction feature is enabled within CloudFront distribution.');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if geo restriction is not enabled within CloudFront distribution.', function (done) {
            const cache = createCache([listDistributions[1]]);
            cloudfrontGeoRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Geo restriction feature is not enabled within CloudFront distribution.');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            cloudfrontGeoRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No CloudFront distributions found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to query for CloudFront distributions', function (done) {
            const cache = createCache([], { message: 'Unable to query for CloudFront distributions' });
            cloudfrontGeoRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for CloudFront distributions');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            cloudfrontGeoRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});