var expect = require('chai').expect;
const cloudfrontLoggingEnabled = require('./cloudfrontLoggingEnabled');

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
                }
            ]
        },
        "OriginGroups": {
            "Quantity": 0
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "S3-cdn-oai/data",
            "TrustedSigners": {
                "Enabled": false,
                "Quantity": 0
            },
            "TrustedKeyGroups": {
                "Enabled": false,
                "Quantity": 0
            },
            "ViewerProtocolPolicy": "https-only",
            "AllowedMethods": {
                "Quantity": 2,
                "Items": [
                    "HEAD",
                    "GET"
                ],
            },
        },
    }
];

const getDistribution = [
    {
        "ETag": "EHQJVBQTCVNEN",
        "Distribution": {
            "Id": "E1JHW5DZR5X4HW",
            "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
            "DistributionConfig": {
                "DefaultRootObject": "",
                "OriginGroups": {
                    "Quantity": 0
                },
                "Logging": {
                    "Enabled": true,
                    "IncludeCookies": false,
                    "Bucket": "s3://abc",
                    "Prefix": "logs/"
                },
            }
        }
    },
    {
        "ETag": "EHQJVBQTCVNEN",
        "Distribution": {
            "Id": "E1JHW5DZR5X4HW",
            "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
            "DistributionConfig": {
                "DefaultRootObject": "",
                "OriginGroups": {
                    "Quantity": 0
                },
                "Logging": {
                    "Enabled": false,
                    "IncludeCookies": false,
                    "Bucket": "",
                    "Prefix": ""
                },
            }
        }
    }
];

const createCache = (data, err, getData, getErr) => {
    var distributionId = (data && data.length) ? data[0].Id : null;
    return {
        cloudfront: {
            listDistributions: {
                'us-east-1': {
                    data: data,
                    err: err
                }
            },
            getDistribution: {
                'us-east-1': {
                    [distributionId]: {
                        data: getData,
                        err: getErr
                    }
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

describe('cloudfrontLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if Request logging is enabled', function (done) {
            const cache = createCache([listDistributions[0]], null, getDistribution[0]);
            cloudfrontLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Request logging is not enabled', function (done) {
            const cache = createCache([listDistributions[0]], null, getDistribution[1]);
            cloudfrontLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            cloudfrontLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            cloudfrontLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to get distributions', function (done) {
            const cache = createCache([listDistributions[0]], null, null, { message: 'Unable to get distribution'});
            cloudfrontLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            cloudfrontLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});