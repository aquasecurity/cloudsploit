var expect = require('chai').expect;
var acmCertificateHasTags = require('./acmCertificateHasTags');

const createCache = (clsuterData, rgData) => {
    return {
        acm: {
            listCertificates: {
                'us-east-1': {
                    err: null,
                    data: clsuterData
                }
            }
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
    }
};

describe('acmCertificateHasTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to list acm certificates', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list ACM certificates');
                done()
            };

            const cache = createCache(null, []);
            acmCertificateHasTags.run(cache, {}, callback);
        });

        it('should give passing result if acm certificates not found.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No ACM certificates found');
                done();
            };
            const cache = createCache([], null);
            acmCertificateHasTags.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources');
                done();
            };

            const cache = createCache(
                [{
                    CertificateArn: 'arn:aws:acm:us-east-1:000011112222:certificate/f256ec8d-80d9-4473-a2b2-ac32cb6fe6e8'
                }],
                null
            );

            acmCertificateHasTags.run(cache, {}, callback);
        });

        it('should give passing result if acm certificates have tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ACM certificate has tags');
                done();
            };
            const cache = createCache(
               [{
                    CertificateArn: 'arn:aws:acm:us-east-1:000011112222:certificate/f256ec8d-80d9-4473-a2b2-ac32cb6fe6e8'
                }],
                [{
                    "ResourceARN": 'arn:aws:acm:us-east-1:000011112222:certificate/f256ec8d-80d9-4473-a2b2-ac32cb6fe6e8',
                    "Tags": [{key:"key1", value:"value"}],
                }]
            );
            acmCertificateHasTags.run(cache, {}, callback);
        });

        it('should give failing result if eks cluster does not have tags', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].region).to.equal('us-east-1');
                    expect(results[0].message).to.include('ACM certificate does not have any tags');
                    done();
                };

               const cache = createCache(
                 [{
                    CertificateArn: 'arn:aws:acm:us-east-1:000011112222:certificate/f256ec8d-80d9-4473-a2b2-ac32cb6fe6e8'
                }],
                [{
                    "ResourceARN":'arn:aws:acm:us-east-1:000011112222:certificate/f256ec8d-80d9-4473-a2b2-ac32cb6fe6e8',
                    "Tags": [],
                }]
            );

            acmCertificateHasTags.run(cache, {}, callback);
        });

    });
});