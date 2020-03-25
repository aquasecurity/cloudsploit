var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./bootVolumeTransitEncryption');

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
        bootVolumeAttachment: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
    }
};

describe('bootVolumeTransitEncryption', function () {
    describe('run', function () {
        it('should give unknown result if a boot volume attachment error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for boot volume attachments')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no boot volume attachment records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No boot volume attachments found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if there is a boot volume without transit encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('boot volume transit encryption is disabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "giotest1",
                        "freeformTags": {},
                        "systemTags": {},
                        "id": "ocid1.volume.oc1.iad.bauwcljtquhbwu5divro64gimkrnfdaxo43cy44cbpuz42g652ol4gw6qsnf",
                        "isHydrated": true,
                        "kmsKeyId": null,
                        "lifecycleState": "AVAILABLE",
                        "performanceTier": null,
                        "vpusPerGB": null,
                        "sizeInGBs": 1024,
                        "sizeInMBs": 1048576,
                        "sourceDetails": null,
                        "timeCreated": "2019-08-29T21:46:01.836Z",
                        "volumeGroupId": null
                    }
                ],
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if all boot volumes have transit encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('boot volume transit encryption is enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "definedTags": {},
                        "displayName": "giotest1",
                        "freeformTags": {},
                        "systemTags": {},
                        "id": "ocid1.volume.oc1.iad.abuwcljtquhbwu5divro64gimkrnfdaxo43cy44cbpuz42g652ol4gw6qsma",
                        "isHydrated": true,
                        "kmsKeyId": null,
                        "lifecycleState": "AVAILABLE",
                        "performanceTier": null,
                        "vpusPerGB": null,
                        "sizeInGBs": 1024,
                        "sizeInMBs": 1048576,
                        "sourceDetails": null,
                        "timeCreated": "2019-08-29T21:46:01.836Z",
                        "volumeGroupId": null,
                        "isPvEncryptionInTransitEnabled": true
                    }
                ],
            );

            plugin.run(cache, {}, callback);
        })
    })
})