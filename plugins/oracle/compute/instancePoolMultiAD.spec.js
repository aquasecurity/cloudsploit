var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instancePoolMultiAD');

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

        instancePool: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('instancePoolMultiAD', function () {
    describe('run', function () {
        it('should give unknown result if an instance pool error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for instance pools')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no instance pool records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No instance pools found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if instance pools have multiple availability domains', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Instance pool is in multiple availability domains')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "ocid1.instancepool.oc1.iad.aaaaaaaaxll7ca2n7sxaakbxyhm6ubn5f7tqc4j2kxr2ucy7i5h74qul3rpq",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "instance-pool-20190807-1340",
                        "instanceConfigurationId": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaahfjaolm2qxtslfce2hcvfyhvqatcrra25iqft6xo6us2msfunyda",
                        "lifecycleState": "RUNNING",
                        "availabilityDomains": [
                            "fMgC:US-ASHBURN-AD-1",
                            "fMgC:US-ASHBURN-AD-2",
                            "fMgC:US-ASHBURN-AD-3"
                        ],
                        "size": 0,
                        "timeCreated": "2019-08-07T20:41:06.811Z",
                        "definedTags": {},
                        "freeformTags": {},
                        "timeStateUpdated": "2019-08-07T20:41:06.811Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if instance pools have only one availability domain', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Instance pool is only in one availability domain')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "instance-pool-20190805-1436",
                        "instanceConfigurationId": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaacsmqbsufpjlyzip2w4pvkbkgle2bsf6wkahxyuvonuqjlyckad5q",
                        "lifecycleState": "RUNNING",
                        "availabilityDomains": [
                            "fMgC:US-ASHBURN-AD-1"
                        ],
                        "size": 1,
                        "timeCreated": "2019-08-05T21:37:11.423Z",
                        "definedTags": {},
                        "freeformTags": {},
                        "timeStateUpdated": "2019-08-06T18:52:57.650Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if instance pools have no availability domains', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No availability domains')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "instance-pool-20190805-1436",
                        "instanceConfigurationId": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaacsmqbsufpjlyzip2w4pvkbkgle2bsf6wkahxyuvonuqjlyckad5q",
                        "lifecycleState": "RUNNING",
                        "size": 1,
                        "timeCreated": "2019-08-05T21:37:11.423Z",
                        "definedTags": {},
                        "freeformTags": {},
                        "timeStateUpdated": "2019-08-06T18:52:57.650Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})