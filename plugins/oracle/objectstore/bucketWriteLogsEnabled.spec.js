var expect = require('chai').expect;
var plugin = require('./bucketWriteLogsEnabled');

const buckets = [
    {
        "namespace": 'idacicrnmktm',
        "name": 'my-bucket',
        "id": 'ocid1.bucket.oc1.iad.111111111111111122222222222222222233333333333333333',
        "compartmentId": 'ocid1.tenancy.oc1..11111111111111111222222222222222222333333333333333',
        "createdBy": 'ocid1.user.oc1..11111111111111112222222222222223333333333333333',
        "timeCreated": '2021-04-28T13:26:51.917Z',
    },
    {
        "namespace": 'idacicrnmktm',
        "name": 'my-bucket-1',
        "id": 'ocid1.bucket.oc1.iad.111111111111111122222222222222222233333333333333333',
        "compartmentId": 'ocid1.tenancy.oc1..11111111111111111222222222222222222333333333333333',
        "createdBy": 'ocid1.user.oc1..11111111111111112222222222222223333333333333333',
        "timeCreated": '2021-04-28T13:26:51.917Z',
    }
];

const logs = [
    {
        "id": "ocid1.log.oc1.log11111111",
        "logGroupId": "ocid1.loggroup.oc1.loggroup11111",
        "displayName": "bucket_log",
        "isEnabled": true,
        "lifecycleState": "ACTIVE",
        "logType": "SERVICE",
        "configuration": {
          "compartmentId": "ocid1.tenancy.oc1.1111111111111",
          "source": {
            "sourceType": "OCISERVICE",
            "service": "objectstorage",
            "resource": "my-bucket-1",
            "category": "write",
            "parameters": {}
          },
          "archiving": {
            "isEnabled": false
          }
        },
        "freeformTags": {},
        "timeCreated": "2022-07-15T00:25:53.258Z",
        "timeLastModified": "2022-07-15T00:25:53.258Z",
        "retentionDuration": 30,
        "compartmentId": "ocid1.tenancy.oc1.1111111111111",
        "logGroups": "ocid1.loggroup.oc1.loggroup11111"
      }
]

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
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        log: {
            list: {
                'us-ashburn-1': {
                    err: null,
                    data: logs
                }
            }
        }
    }
};

describe('bucketWriteLogsEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a bucket error occurs or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for object store buckets')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no buckets are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No object store buckets to check')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if the bucket does not have write level logs enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The bucket does not have write level logging enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [buckets[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if the bucket has write level logs enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('The bucket has write level logging enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [buckets[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})