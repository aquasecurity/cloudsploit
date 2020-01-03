var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./dbSSLEnabled');

const createCache = (err, data) => {
    return {
        instances: {
            sql: {
                list: {
                    'global': {
                        err: err,
                        data: data
                    }
                }
            }
        }
    }
};

describe('dbSSLEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a sql instance error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query SQL instances');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no sql instances are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL instances found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if SSL is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL database has SSL enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "sql#instance",
                        "state": "RUNNABLE",
                        "databaseVersion": "MYSQL_5_7",
                        "settings": {
                            "authorizedGaeApplications": [],
                            "tier": "db-f1-micro",
                            "kind": "sql#settings",
                            "availabilityType": "ZONAL",
                            "pricingPlan": "PER_USE",
                            "replicationType": "SYNCHRONOUS",
                            "activationPolicy": "ALWAYS",
                            "ipConfiguration": {
                                "authorizedNetworks": [],
                                "ipv4Enabled": true,
                                "requireSsl": true
                            },
                            "locationPreference": {
                                "zone": "us-east1-c",
                                "kind": "sql#locationPreference"
                            },
                            "dataDiskType": "PD_HDD",
                            "maintenanceWindow": {
                                "kind": "sql#maintenanceWindow",
                                "hour": 0,
                                "day": 0
                            },
                            "backupConfiguration": {
                                "startTime": "22:00",
                                "kind": "sql#backupConfiguration",
                                "enabled": true,
                                "binaryLogEnabled": true
                            },
                            "settingsVersion": "4",
                            "storageAutoResizeLimit": "0",
                            "storageAutoResize": true,
                            "dataDiskSizeGb": "10"
                        },
                        "etag": "5b3b8471ede5b88da8e005062775991862c410f94b6630248538a5fc1bfa41d5",
                        "ipAddresses": [
                            {
                                "type": "PRIMARY",
                                "ipAddress": "35.243.130.180"
                            }
                        ],
                        "serverCaCert": {
                            "kind": "sql#sslCert",
                            "certSerialNumber": "0",
                            "cert": "-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
                            "commonName": "C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA,dnQualifier=46cb275a-4353-4e26-a5b1-520b308e2cdd",
                            "sha1Fingerprint": "2b52389388e33f560f7c7d40157ffb77ab6af64f",
                            "instance": "mysqltest1",
                            "createTime": "2019-11-05T01:37:13.099Z",
                            "expirationTime": "2029-11-02T01:38:13.099Z"
                        },
                        "instanceType": "CLOUD_SQL_INSTANCE",
                        "project": "rosy-booth-253119",
                        "serviceAccountEmailAddress": "p293348421062-t9yegr@gcp-sa-cloud-sql.iam.gserviceaccount.com",
                        "backendType": "SECOND_GEN",
                        "selfLink": "https://www.googleapis.com/sql/v1beta4/projects/rosy-booth-253119/instances/mysqltest1",
                        "connectionName": "rosy-booth-253119:us-east1:mysqltest1",
                        "name": "mysqltest1",
                        "region": "us-east1",
                        "gceZone": "us-east1-c"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if monitoring is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL database has SSL disabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "sql#instance",
                        "state": "RUNNABLE",
                        "databaseVersion": "MYSQL_5_7",
                        "settings": {
                            "authorizedGaeApplications": [],
                            "tier": "db-f1-micro",
                            "kind": "sql#settings",
                            "availabilityType": "ZONAL",
                            "pricingPlan": "PER_USE",
                            "replicationType": "SYNCHRONOUS",
                            "activationPolicy": "ALWAYS",
                            "ipConfiguration": {
                                "authorizedNetworks": [],
                                "ipv4Enabled": true,
                            },
                            "locationPreference": {
                                "zone": "us-east1-c",
                                "kind": "sql#locationPreference"
                            },
                            "dataDiskType": "PD_HDD",
                            "maintenanceWindow": {
                                "kind": "sql#maintenanceWindow",
                                "hour": 0,
                                "day": 0
                            },
                            "backupConfiguration": {
                                "startTime": "22:00",
                                "kind": "sql#backupConfiguration",
                                "enabled": true,
                                "binaryLogEnabled": true
                            },
                            "settingsVersion": "4",
                            "storageAutoResizeLimit": "0",
                            "storageAutoResize": true,
                            "dataDiskSizeGb": "10"
                        },
                        "etag": "5b3b8471ede5b88da8e005062775991862c410f94b6630248538a5fc1bfa41d5",
                        "ipAddresses": [
                            {
                                "type": "PRIMARY",
                                "ipAddress": "35.243.130.180"
                            }
                        ],
                        "serverCaCert": {
                            "kind": "sql#sslCert",
                            "certSerialNumber": "0",
                            "cert": "-----BEGIN CERTIFICATE----------END CERTIFICATE-----",
                            "commonName": "C=US,O=Google\\, Inc,CN=Google Cloud SQL Server CA,dnQualifier=46cb275a-4353-4e26-a5b1-520b308e2cdd",
                            "sha1Fingerprint": "2b52389388e33f560f7c7d40157ffb77ab6af64f",
                            "instance": "mysqltest1",
                            "createTime": "2019-11-05T01:37:13.099Z",
                            "expirationTime": "2029-11-02T01:38:13.099Z"
                        },
                        "instanceType": "CLOUD_SQL_INSTANCE",
                        "project": "rosy-booth-253119",
                        "serviceAccountEmailAddress": "p293348421062-t9yegr@gcp-sa-cloud-sql.iam.gserviceaccount.com",
                        "backendType": "SECOND_GEN",
                        "selfLink": "https://www.googleapis.com/sql/v1beta4/projects/rosy-booth-253119/instances/mysqltest1",
                        "connectionName": "rosy-booth-253119:us-east1:mysqltest1",
                        "name": "mysqltest1",
                        "region": "us-east1",
                        "gceZone": "us-east1-c"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})