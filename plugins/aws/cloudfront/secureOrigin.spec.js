var expect = require('chai').expect;
const secureOrigin = require('./secureOrigin');

const listDistributions = [
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Items": [
                {
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                        "OriginSslProtocols": {
                            "Quantity": 4,
                            "Items": [
                                "SSLv3",
                                "TLSv1",
                                "TLSv1.1",
                                "TLSv1.2"
                            ]
                        },
                        "OriginReadTimeout": 30,
                        "OriginKeepaliveTimeout": 5
                    },
                }
            ]
        }
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Items": [
                {
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {
                            "Quantity": 4,
                            "Items": [
                                "SSLv3",
                                "TLSv1",
                                "TLSv1.1",
                                "TLSv1.2"
                            ]
                        },
                        "OriginReadTimeout": 30,
                        "OriginKeepaliveTimeout": 5
                    },
                }
            ]
        }
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Items": [
                {
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "match-viewer",
                        "OriginSslProtocols": {
                            "Quantity": 3,
                            "Items": [
                                "TLSv1",
                                "TLSv1.1",
                                "TLSv1.2"
                            ]
                        },
                    },
                }
            ]
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Items": [
                {
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "match-viewer",
                        "OriginSslProtocols": {
                            "Quantity": 3,
                            "Items": [
                                "SSLv3",
                                "TLSv1.1",
                                "TLSv1.2"
                            ]
                        },
                    },
                }
            ]
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

describe('secureOrigin', function () {
    describe('run', function () {
        it('should PASS if CloudFront origin is using https-only', function (done) {
            const cache = createCache([listDistributions[1]]);
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should WARN if CloudFront origin is using match-viewer', function (done) {
            const cache = createCache([listDistributions[2]]);
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(1);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if CloudFront origin is using http-only', function (done) {
            const cache = createCache([listDistributions[0]]);
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if CloudFront origin is using SSLv3 and TLSv1 protocols', function (done) {
            const cache = createCache([listDistributions[1]]);
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[1].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if CloudFront origin is using SSLv3 protocols', function (done) {
            const cache = createCache([listDistributions[3]]);
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[1].region).to.equal('global');
                done();
            });
        });

        it('should WARN if CloudFront origin is using TLSv1 protocol', function (done) {
            const cache = createCache([listDistributions[2]]);
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(1);
                expect(results[1].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            secureOrigin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});