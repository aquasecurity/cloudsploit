var expect = require('chai').expect;
const insecureProtocols = require('./insecureProtocols');

const listDistributions = [
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "ViewerCertificate": {
            "CloudFrontDefaultCertificate": true,
            "MinimumProtocolVersion": "TLSv1",
            "CertificateSource": "cloudfront"
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "ViewerCertificate": {
            "CloudFrontDefaultCertificate": true,
            "MinimumProtocolVersion": "TLSv1",
            "CertificateSource": "cloudfront"
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "ViewerCertificate": {
            "MinimumProtocolVersion": "SSLv3",
            "CertificateSource": "cloudfront"
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "ViewerCertificate": {
            "MinimumProtocolVersion": "TLSv1",
            "CertificateSource": "cloudfront"
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "ViewerCertificate": {
            "MinimumProtocolVersion": "TLSv1_2016",
            "CertificateSource": "cloudfront"
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "ViewerCertificate": {
            "MinimumProtocolVersion": "TLSv1.1_2016",
            "CertificateSource": "cloudfront"
        },
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "ViewerCertificate": {
            "MinimumProtocolVersion": "TLSv1.2_2018",
            "CertificateSource": "cloudfront"
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

describe('insecureProtocols', function () {
    describe('run', function () {
        it('should PASS if Distribution is not configured for SSL delivery', function (done) {
            const cache = createCache([listDistributions[0]]);
            insecureProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if Distribution is using secure default certificate', function (done) {
            const cache = createCache([listDistributions[1]]);
            insecureProtocols.run(cache, { insecure_cloudfront_ignore_default: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Distribution is using the insecure default CloudFront TLS certificate', function (done) {
            const cache = createCache([listDistributions[2]]);
            insecureProtocols.run(cache, { insecure_cloudfront_ignore_default: 'false' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Distribution is using insecure SSLv3', function (done) {
            const cache = createCache([listDistributions[3]]);
            insecureProtocols.run(cache, { insecure_cloudfront_ignore_default: 'false' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Distribution is using insecure TLSv1.0', function (done) {
            const cache = createCache([listDistributions[4]]);
            insecureProtocols.run(cache, { insecure_cloudfront_ignore_default: 'false' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if Distribution is using insecure TLSv1_2016', function (done) {
            const cache = createCache([listDistributions[5]]);
            insecureProtocols.run(cache, { insecure_cloudfront_ignore_default: 'false' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if Distribution is using secure TLSv1.1_2016', function (done) {
            const cache = createCache([listDistributions[6]]);
            insecureProtocols.run(cache, { insecure_cloudfront_ignore_default: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if Distribution is using secure TLSv1.2_2018', function (done) {
            const cache = createCache([listDistributions[7]]);
            insecureProtocols.run(cache, { insecure_cloudfront_ignore_default: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            insecureProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            insecureProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should not return any results if list distributions response not found', function (done) {
            const cache = createNullCache();
            insecureProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});