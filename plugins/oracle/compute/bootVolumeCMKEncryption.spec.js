var expect = require('chai').expect;
var plugin = require('./bootVolumeCMKEncryption');

const bootVolumes = [
    {
        "compartmentId": "ocid1.tenancy.oc1.aaaaaa.111111",
        "definedTags": {},
        "displayName": "vol-2",
        "freeformTags": {},
        "systemTags": {},
        "id": "ocid1.volume.oc1.aaaaaa.1111111",
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
    },
    {
        "compartmentId": "ocid1.tenancy.oc1.aaaaaa.111111",
        "definedTags": {},
        "displayName": "vol-2",
        "freeformTags": {},
        "systemTags": {},
        "id": "ocid1.volume.oc1.aaaaaa.1111111",
        "isHydrated": true,
        "lifecycleState": "AVAILABLE",
        "performanceTier": null,
        "vpusPerGB": null,
        "sizeInGBs": 1024,
        "sizeInMBs": 1048576,
        "sourceDetails": null,
        "timeCreated": "2019-08-29T21:46:01.836Z",
        "volumeGroupId": null,
        "kmsKeyId": 'key-1'
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
        bootVolume: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        vault: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                            "compartmentId": "compartment-1",
                            "displayName": "vault-1",
                            "freeformTags": {},
                            "id": "vault-1",
                            "lifecycleState": "ACTIVE",
                        },
                    ]
                }
            }
        },
        keys: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                            "compartmentId": "compartment-1",
                            "definedTags": {},
                            "displayName": "key-1",
                            "freeformTags": {},
                            "id": "key-1",
                            "lifecycleState": "ENABLED",
                            "timeCreated": "2022-04-30T19:49:12.841Z",
                            "vaultId": "vault-1",
                            "protectionMode": "SOFTWARE",
                            "algorithm": "AES"
                        }
                    ],
                
                }
            }
        }
    }
};

describe('bootVolumeCMKEncryption', function () {
    describe('run', function () {
        it('should give unknown result if a boot volume error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for boot volumes')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no boot volumes are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No boot volumes found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })


        it('should give failing result if boot volume does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('which is less')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [bootVolumes[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if boot volume has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('which is greater than or equal to')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [bootVolumes[1]]
            );

            plugin.run(cache, {}, callback);
        });
    });
});