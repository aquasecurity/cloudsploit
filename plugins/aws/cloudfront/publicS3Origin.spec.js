var expect = require('chai').expect;
const publicS3Origin = require('./publicS3Origin');

const listDistributions = [
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "S3-cdn-oai/data",
                    "DomainName": "cdn-oai.s3.amazonaws.com",
                    "OriginPath": "/data",
                    "S3OriginConfig": {
                        "OriginAccessIdentity": null
                    },
                }
            ]
        },
        "OriginGroups": {
            "Quantity": 0
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "S3-cdn-oai/data",
                    "DomainName": "cdn-oai.s3.amazonaws.com",
                    "OriginPath": "/data",
                    "S3OriginConfig": {
                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E1FNBIV9X9FNYA"
                    },
                }
            ]
        },
        "OriginGroups": {
            "Quantity": 0
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "S3-cdn-oai/data",
                    "DomainName": "cdn-oai.s3.amazonaws.com",
                    "OriginPath": "/data",
                }
            ]
        },
        "OriginGroups": {
            "Quantity": 0
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

describe('publicS3Origin', function () {
    describe('run', function () {
        it('should PASS if CloudFront distribution origin is not setup without an origin access identity', function (done) {
            const cache = createCache([listDistributions[1]]);
            publicS3Origin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if CloudFront CloudFront distribution is using an S3 origin without an origin access identity', function (done) {
            const cache = createCache([listDistributions[0]]);
            publicS3Origin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            publicS3Origin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            publicS3Origin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            publicS3Origin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});