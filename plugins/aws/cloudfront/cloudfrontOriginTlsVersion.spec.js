var expect = require('chai').expect;
const cloudfrontOriginTLSVersion = require('./cloudfrontOriginTlsVersion');

const listDistributions = [
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "WebACLId": "ca44237b-b1d8-46b2-abad-ada48c7f0894",
        "Origins": {
            "Items":[
        {
        "CustomOriginConfig": {
        "OriginSslProtocols": {
            "Items": [    
                'SSLv3',
                'TLSv1',
            ]}}}
        ]},
        'ViewerCertificate': {
            'MinimumProtocolVersion': 'TLSv1.2_2018'
        }
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Items":[
       { 
        "CustomOriginConfig": {
        "OriginSslProtocols": {
            "Items": [    
                'TLSv1.2',
            ]}}
            }]
        },
        'ViewerCertificate': {
            'MinimumProtocolVersion': 'TLSv1.2_2021'
        }
    },
    {
        "Id": "E1JHW5DZR5X4HW",
        "ARN": "arn:aws:cloudfront::111122223333:distribution/E1JHW5DZR5X4HW",
        "Origins": {
            "Items": []
        },
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

describe('cloudfrontOriginTLSVersion', function () {
    describe('run', function () {
        it('should PASS if CloudFront distributions custom origin TLS version is not deprecated', function (done) {
            const cache = createCache([listDistributions[1]]);
            cloudfrontOriginTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('CloudFront distribution custom origin TLS version is not deprecated')
                done();
            });
        });

        it('should PASS if CloudFront distributions has no origins', function (done) {
            const cache = createCache([listDistributions[2]]);
            cloudfrontOriginTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('CloudFront distribution has no origins')
                done();
            });
        });
        it('should FAIL if CloudFront Distribution custom origin TLS version is deprecated', function (done) {
            const cache = createCache([listDistributions[0]]);
            cloudfrontOriginTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('CloudFront distribution custom origin TLS version is deprecated')
                done();
            });
        });

        it('should PASS if no CloudFront distributions found', function (done) {
            const cache = createCache([]);
            cloudfrontOriginTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('No CloudFront distributions found')
                done();
            });
        });

        it('should UNKNOWN if unable to list distributions', function (done) {
            const cache = createCache([], { message: 'Unable to list distributions' });
            cloudfrontOriginTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
                expect(results[0].message).to.include('Unable to query for CloudFront distributions')
                done();
            });
        });
    });
});