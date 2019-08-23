var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./autoscaleEnabled');

const createCache = (instancePoolErr, autoscaleErr, instancePoolData, autoscaleData) => {
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
                "us-ashburn-1": {
                    data: instancePoolData,
                    err: instancePoolErr
                }
            }
        },
        autoscaleConfiguration: {
            list: {
                "us-ashburn-1": {
                    data: autoscaleData,
                    err: autoscaleErr
                }
            }
        }
    }
};

describe('autoscaleEnabled', function () {
    describe('run', function () {
        it('should give unknown result if an Instance Pool error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for instance Pools')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
                null,
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no Instance Pool records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No Instance Pool found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                [],
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give unknown result if a autoscale error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[5].status).to.equal(3)
                expect(results[5].message).to.include('Unable to query for Autoscale Configurations')
                expect(results[5].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                ['hello', 'hi'],

                [
                    {
                        "id": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "instance-pool-20190805-1436",
                        "instanceConfigurationId": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaacsmqbsufpjlyzip2w4pvkbkgle2bsf6wkahxyuvonuqjlyckad5q",
                        "lifecycleState": "SCALING",
                        "availabilityDomains": [
                            "fMgC:US-ASHBURN-AD-1"
                        ],
                        "size": 1,
                        "timeCreated": "2019-08-05T21:37:11.423Z",
                        "definedTags": {},
                        "freeformTags": {},
                        "timeStateUpdated": "2019-08-06T18:10:39.767Z"
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result all instance pools have autoscale enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[results.length-1].status).to.equal(0)
                expect(results[results.length-1].message).to.include('All Instance Pools have Autoscale Configured')
                done()
            };

            const cache = createCache(
                null,
                null,
                [
                    {
                        "id": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "instance-pool-20190805-1436",
                        "instanceConfigurationId": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaacsmqbsufpjlyzip2w4pvkbkgle2bsf6wkahxyuvonuqjlyckad5q",
                        "lifecycleState": "SCALING",
                        "availabilityDomains": [
                            "fMgC:US-ASHBURN-AD-1"
                        ],
                        "size": 1,
                        "timeCreated": "2019-08-05T21:37:11.423Z",
                        "definedTags": {},
                        "freeformTags": {},
                        "timeStateUpdated": "2019-08-06T18:10:39.767Z"
                    }
                ],
                [
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "auto-scaling-config-20190806-1049",
                        "id": "ocid1.autoscalingconfiguration.oc1.iad.aaaaaaaat2xgjrisjsj3myraz7eh3bsfrahl7nkl6vimlvfkgawgcvsvacxq",
                        "coolDownInSeconds": 300,
                        "isEnabled": true,
                        "resource": {
                            "type": "instancePool",
                            "id": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa"
                        },
                        "definedTags": {},
                        "freeformTags": {},
                        "timeCreated": "2019-08-06T17:52:45.786Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if instance pools do not have autoscale enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[results.length-1].status).to.equal(2)
                expect(results[results.length-1].message).to.include('These Instance Pools do not have Autoscale Configured')
                done()
            };

            const cache = createCache(
                null,
                null,
                [
                    {
                        "id": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "instance-pool-20190805-1436",
                        "instanceConfigurationId": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaacsmqbsufpjlyzip2w4pvkbkgle2bsf6wkahxyuvonuqjlyckad5q",
                        "lifecycleState": "SCALING",
                        "availabilityDomains": [
                            "fMgC:US-ASHBURN-AD-1"
                        ],
                        "size": 1,
                        "timeCreated": "2019-08-05T21:37:11.423Z",
                        "definedTags": {},
                        "freeformTags": {},
                        "timeStateUpdated": "2019-08-06T18:10:39.767Z"
                    }
                ],
                [
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "displayName": "auto-scaling-config-20190806-1049",
                        "id": "ocid1.autoscalingconfiguration.oc1.iad.aaaaaaaat2xgjrisjsj3myraz7eh3bsfrahl7nkl6vimlvfkgawgcvsvacxq",
                        "coolDownInSeconds": 300,
                        "isEnabled": false,
                        "resource": {
                            "type": "instancePool",
                            "id": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa"
                        },
                        "definedTags": {},
                        "freeformTags": {},
                        "timeCreated": "2019-08-06T17:52:45.786Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})