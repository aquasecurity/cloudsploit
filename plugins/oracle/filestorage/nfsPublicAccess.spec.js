var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./nfsPublicAccess');

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
        exprt: {
            get: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('nfsPublicAccess', function () {
    describe('run', function () {
        it('should give passing result if an error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for File Systems')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No File Systems present')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if there is public access on the File System', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('NFS allows public access')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                        {
                            "exportOptions": [
                                {
                                    "source": "0.0.0.0/0",
                                    "requirePrivilegedSourcePort": false,
                                    "access": "READ_WRITE",
                                    "identitySquash": "NONE",
                                    "anonymousUid": 65534,
                                    "anonymousGid": 65534
                                }
                            ],
                            "exportSetId": "ocid1.exportset.oc1.iad.aaaaaa4np2snjqnanfqwillqojxwiotjmfsc2ylefuzqaaaa",
                            "fileSystemId": "ocid1.filesystem.oc1.iad.aaaaaaaaaaaal26cnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                            "id": "ocid1.export.oc1.iad.aaaaacvippxgdr7nnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                            "lifecycleState": "ACTIVE",
                            "path": "/FileSystem-20190604-2257",
                            "timeCreated": "2019-06-04T22:57:46.291Z"
                        }
                    ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if there isnt public access on the File System', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('NFS does not allow public access')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "exportOptions": [
                            {
                                "source": "192.168.0.1/32",
                                "requirePrivilegedSourcePort": false,
                                "access": "READ_WRITE",
                                "identitySquash": "NONE",
                                "anonymousUid": 65534,
                                "anonymousGid": 65534
                            }
                        ],
                        "exportSetId": "ocid1.exportset.oc1.iad.aaaaaa4np2snjqnanfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "fileSystemId": "ocid1.filesystem.oc1.iad.aaaaaaaaaaaal26cnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "id": "ocid1.export.oc1.iad.aaaaacvippxgdr7nnfqwillqojxwiotjmfsc2ylefuzqaaaa",
                        "lifecycleState": "ACTIVE",
                        "path": "/FileSystem-20190604-2257",
                        "timeCreated": "2019-06-04T22:57:46.291Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})