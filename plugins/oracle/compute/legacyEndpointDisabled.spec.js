var expect = require('chai').expect;
var plugin = require('./legacyEndpointDisabled');

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

        instance: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('legacyEndpointDisabled', function () {
    describe('run', function () {
        it('should give unknown result if an instance error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for instances')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no instance records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No instances found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if instance has legacy endpoints disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Instance has Legacy MetaData service (IMDSv1) endpoints disabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaaaaaa",
                        "dedicatedVmHostId": null,
                        "definedTags": {},
                        "displayName": "instance1",
                        "extendedMetadata": {
                            "compute_management": {
                                "instance_configuration": {
                                    "state": "SUCCEEDED"
                                }
                            }
                        },
                        "faultDomain": "FAULT-DOMAIN-1",
                        "id": "ocid1.instance.oc1",
                        "imageId": "ocid1.image.oc1",
                        "instanceOptions":  { 
                            "areLegacyImdsEndpointsDisabled": true
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if instance does not have legacy endpoints disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Instance does not have Legacy MetaData service (IMDSv1) endpoints disabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaaaaaa",
                        "dedicatedVmHostId": null,
                        "definedTags": {},
                        "displayName": "instance1",
                        "extendedMetadata": {
                            "compute_management": {
                                "instance_configuration": {
                                    "state": "SUCCEEDED"
                                }
                            }
                        },
                        "faultDomain": "FAULT-DOMAIN-1",
                        "id": "ocid1.instance.oc1",
                        "imageId": "ocid1.image.oc1",
                        "instanceOptions":  { 
                            "areLegacyImdsEndpointsDisabled": false
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})