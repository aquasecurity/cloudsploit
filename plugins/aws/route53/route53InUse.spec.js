var expect = require('chai').expect;
var route53InUse = require('./route53InUse');

const createCache = (listHostedZonesData, error = null) => {
    return {
        route53: {
            listHostedZones: {
                'us-east-1': {
                    err: error,
                    data: listHostedZonesData
                }
            }
        }
    };
};

describe('Route 53 In Use', function () {
    describe('run', function () {
        it('should return passing result if Route53 DNS service is in use', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Route53 DNS service is in use');
                done();
            };

            const cache = createCache([
                {
                    "Id": "/hostedzone/Z0959845393J2LOUSNVSK",
                    "Name": "testfr.com.",
                    "CallerReference": "d042e53d-7b8b-4974-94e9-8305af0c6acb",
                    "Config": {
                        "Comment": "",
                        "PrivateZone": false
                    },
                    "ResourceRecordSetCount": 4
                }
            ]);

            route53InUse.run(cache, {}, callback);
        });

        it('should return failing result if Route53 DNS service is not in use', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Route53 DNS service is not in use');
                done();
            };

            const cache = createCache([]);

            route53InUse.run(cache, {}, callback);
        });

        it('should return error result if unable to query for hosted zones', function (done) {
            const errorMessage = 'Error occurred while querying hosted zones';
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include(`Unable to query for hosted zones: ${errorMessage}`);
                done();
            };

            const cache = createCache([], errorMessage);

            route53InUse.run(cache, {}, callback);
        });
    });
});
