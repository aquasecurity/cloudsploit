var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./sqlInstanceLabelsAdded');

const createCache = (err, data) => {
    return {
            sql: {
                list: {
                    'global': {
                        err: err,
                        data: data
                    }
                }
        },
        projects: {
            get: {
                'global': {
                    data: [{ name: 'test-project' }]
                }
            }
        }
    }
};

describe('sqlInstanceLabelsAdded', function () {
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

        it('should give passing result if SQL instance has labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for the SQL database');
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
                            "userLabels": { 'test-2': 'data', 'tes-1': 'label' },
                            "availabilityType": "ZONAL",
                            "pricingPlan": "PER_USE",
                            "replicationType": "SYNCHRONOUS",
                            "activationPolicy": "ALWAYS",
                            "ipConfiguration": {
                                "authorizedNetworks": [],
                                "ipv4Enabled": true,
                                "requireSsl": true
                            }
                        },
                        "etag": "5b3b8471ede5b88da8e005062775991862c410f94b6630248538a5fc1bfa41d5",
                        "ipAddresses": [
                            {
                                "type": "PRIMARY",
                                "ipAddress": "35.243.130.180"
                            }
                        ],
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

        it('should give failing result if sql instance does not have labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have any labels');
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
                            }
                        },
                        "etag": "5b3b8471ede5b88da8e005062775991862c410f94b6630248538a5fc1bfa41d5",
                        "ipAddresses": [
                            {
                                "type": "PRIMARY",
                                "ipAddress": "35.243.130.180"
                            }
                        ],
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