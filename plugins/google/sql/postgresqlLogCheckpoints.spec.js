var expect = require('chai').expect;
var plugin = require('./postgresqlLogCheckpoints');

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

describe('postgresqlLogCheckpoints', function () {
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

        it('should give passing result if instance has log_checkpoints flag enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL instance has log_checkpoints flag enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "sql#instance",
                        "state": "RUNNABLE",
                        "databaseVersion": "POSTGRES_13",
                        "settings": {
                            "authorizedGaeApplications": [],
                            "tier": "db-custom-1-3840",
                            "kind": "sql#settings",
                            "availabilityType": "ZONAL",
                            "pricingPlan": "PER_USE",
                            "replicationType": "SYNCHRONOUS",
                            "activationPolicy": "ALWAYS",
                            "locationPreference": {
                                "zone": "us-central1-f",
                                "kind": "sql#locationPreference"
                            },
                            "databaseFlags": [
                                {
                                "name": "log_checkpoints",
                                "value": "on"
                                }
                            ],
                            "dataDiskType": "PD_HDD",
                            "maintenanceWindow": {
                                "kind": "sql#maintenanceWindow",
                                "hour": 0,
                                "day": 0
                            },
                            "settingsVersion": "3",
                            "storageAutoResizeLimit": "0",
                            "storageAutoResize": false,
                            "dataDiskSizeGb": "10"
                        },
                        "instanceType": "CLOUD_SQL_INSTANCE",
                        "name": "aqua-instance",
                        "region": "us-central1",
                        "gceZone": "us-central1-f"
                    }
                ]                  
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if instance does not have log_checkpoints flag enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL instance does not have log_checkpoints flag enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "sql#instance",
                        "state": "RUNNABLE",
                        "databaseVersion": "POSTGRES_13",
                        "settings": {
                            "authorizedGaeApplications": [],
                            "tier": "db-custom-1-3840",
                            "kind": "sql#settings",
                            "availabilityType": "ZONAL",
                            "pricingPlan": "PER_USE",
                            "replicationType": "SYNCHRONOUS",
                            "activationPolicy": "ALWAYS",
                            "locationPreference": {
                                "zone": "us-central1-f",
                                "kind": "sql#locationPreference"
                            },
                            "databaseFlags": [
                                {
                                "name": "log_checkpoints",
                                "value": "off"
                                }
                            ],
                            "dataDiskType": "PD_HDD",
                            "maintenanceWindow": {
                                "kind": "sql#maintenanceWindow",
                                "hour": 0,
                                "day": 0
                            },
                            "settingsVersion": "3",
                            "storageAutoResizeLimit": "0",
                            "storageAutoResize": false,
                            "dataDiskSizeGb": "10"
                        },
                        "instanceType": "CLOUD_SQL_INSTANCE",
                        "name": "aqua-instance",
                        "region": "us-central1",
                        "gceZone": "us-central1-f"
                    }
                ]   
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if instance does not support log_checkpoints flag', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance database version is not of PosgreSQL type');
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
                            "tier": "db-custom-1-3840",
                            "kind": "sql#settings",
                            "availabilityType": "ZONAL",
                            "pricingPlan": "PER_USE",
                            "replicationType": "SYNCHRONOUS",
                            "activationPolicy": "ALWAYS",
                            "locationPreference": {
                                "zone": "us-central1-f",
                                "kind": "sql#locationPreference"
                            },
                            "databaseFlags": [],
                            "dataDiskType": "PD_HDD",
                            "maintenanceWindow": {
                                "kind": "sql#maintenanceWindow",
                                "hour": 0,
                                "day": 0
                            },
                            "settingsVersion": "3",
                            "storageAutoResizeLimit": "0",
                            "storageAutoResize": false,
                            "dataDiskSizeGb": "10"
                        },
                        "instanceType": "CLOUD_SQL_INSTANCE",
                        "name": "aqua-instance",
                        "region": "us-central1",
                        "gceZone": "us-central1-f"
                    }
                ]   
            );

            plugin.run(cache, {}, callback);
        })
    })
})
