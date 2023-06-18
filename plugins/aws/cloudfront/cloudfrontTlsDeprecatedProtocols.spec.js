var expect = require('chai').expect;
const cloudfrontTLSVersion = require('./cloudfrontTlsDeprecatedProtocols');

const listDistributions = [
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "WebACLId": "ca44237b-b1d8-46b2-abad-ada48c7f0894",
        'ViewerCertificate': {
            'MinimumProtocolVersion': 'TLSv1'
        }
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        'ViewerCertificate': {
            'MinimumProtocolVersion': 'TLSv1.2_2021'
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

describe('cloudfrontTLSVersion', function () {
    describe('run', function () {
        it('should PASS if CloudFront distributions TLS version is not deprecated', function (done) {
            const cache = createCache([listDistributions[1]]);
            cloudfrontTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('CloudFront distribution is not using deprecated TLS version')
                done();
            });
        });

        it('should FAIL if Cloudfront DistributionTLS version is deprecated', function (done) {
            const cache = createCache([listDistributions[0]]);
            cloudfrontTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('CloudFront distribution is using deprecated TLS version')
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            cloudfrontTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('No CloudFront distributions found')
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            cloudfrontTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('Unable to query for CloudFront distributions')
                done();
            });
        });
    });
});