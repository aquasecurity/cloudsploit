var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./dbBackupEnabled');

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
        database: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('dbBackupEnabled', function () {
    describe('run', function () {
        it('should give unknown result if an error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for databases:')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['hello'],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No databases found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if database auto backup is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The database has auto backup disabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "characterSet": "AL32UTF8",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "connectionStrings": null,
                        "dbBackupConfig": {
                            "autoBackupEnabled": false,
                            "autoBackupWindow": null,
                            "backupDestinationDetails": null,
                            "recoveryWindowInDays": null,
                            "remoteBackupEnabled": null,
                            "remoteRegion": null
                        },
                        "dbDomain": null,
                        "dbHomeId": "ocid1.dbhome.oc1.iad.abuwcljrqtb5ubpm7zajyzvsgs3h27e6ruqhtu4jchumvlwdyze6tz5b5zfq",
                        "dbName": "DB0806",
                        "dbUniqueName": "DB0806_iad2nw",
                        "dbWorkload": "OLTP",
                        "definedTags": {},
                        "freeformTags": {},
                        "id": "ocid1.database.oc1.iad.abuwcljrsgaiprt577yzwgynx5oqkwd5up5ycig3sgtyjod5dwgwnt2okuha",
                        "lastBackupTimestamp": null,
                        "lastRemoteBackupTimestamp": null,
                        "lifecycleDetails": null,
                        "lifecycleState": "TERMINATED",
                        "ncharacterSet": "AL16UTF16",
                        "pdbName": null,
                        "timeCreated": "2019-08-06T19:44:15.503Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if database auto backup is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('The database has auto backup enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "characterSet": "AL32UTF8",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "connectionStrings": null,
                        "dbBackupConfig": {
                            "autoBackupEnabled": true,
                            "autoBackupWindow": null,
                            "backupDestinationDetails": null,
                            "recoveryWindowInDays": null,
                            "remoteBackupEnabled": null,
                            "remoteRegion": null
                        },
                        "dbDomain": null,
                        "dbHomeId": "ocid1.dbhome.oc1.iad.abuwcljrqtb5ubpm7zajyzvsgs3h27e6ruqhtu4jchumvlwdyze6tz5b5zfq",
                        "dbName": "DB0806",
                        "dbUniqueName": "DB0806_iad2nw",
                        "dbWorkload": "OLTP",
                        "definedTags": {},
                        "freeformTags": {},
                        "id": "ocid1.database.oc1.iad.abuwcljrsgaiprt577yzwgynx5oqkwd5up5ycig3sgtyjod5dwgwnt2okuha",
                        "lastBackupTimestamp": null,
                        "lastRemoteBackupTimestamp": null,
                        "lifecycleDetails": null,
                        "lifecycleState": "TERMINATED",
                        "ncharacterSet": "AL16UTF16",
                        "pdbName": null,
                        "timeCreated": "2019-08-06T19:44:15.503Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
    });
});