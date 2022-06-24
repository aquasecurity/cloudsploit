var expect = require('chai').expect;
var plugin = require('./bucketPublicAccessType');

const getBucket = [
    {
        "namespace": 'idacicrnmktm',
        "name": 'my-bucket',
        "id": 'ocid1.bucket.oc1.iad.111111111111111122222222222222222233333333333333333',
        "compartmentId": 'ocid1.tenancy.oc1..11111111111111111222222222222222222333333333333333',
        "createdBy": 'ocid1.user.oc1..11111111111111112222222222222223333333333333333',
        "timeCreated": '2021-04-28T13:26:51.917Z',
        "publicAccessType": 'NoPublicAccess',
    },
    {
        "namespace": 'idacicrnmktm',
        "name": 'akhtar-bucket',
        "id": 'ocid1.bucket.oc1.iad.111111111111111122222222222222222233333333333333333',
        "compartmentId": 'ocid1.tenancy.oc1..11111111111111111222222222222222222333333333333333',
        "createdBy": 'ocid1.user.oc1..11111111111111112222222222222223333333333333333',
        "timeCreated": '2021-04-28T13:26:51.917Z',
        "publicAccessType": 'ObjectRead'
    }
];

const createCache = (err, data) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        bucket: {
            get: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('bucketPublicAccessType', function () {
    describe('run', function () {
        it('should give unknown result if unable to query for object store bucket details', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for object store bucket details')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['hello'],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no object store buckets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No object store bucket details to check')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if bucket allows public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('allows')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [getBucket[1]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if bucket does not allow public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('does not allow public access')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [getBucket[0]]
            );

            plugin.run(cache, {}, callback);
        });
    });
});