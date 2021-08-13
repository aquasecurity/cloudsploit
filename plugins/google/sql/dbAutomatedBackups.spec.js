var expect = require('chai').expect;
var plugin = require('./dbAutomatedBackups');

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

describe('dbAutomatedBackups', function () {
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
        it('should give passing result if no sql instances found', function (done) {
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
        it('should give passing result if automated backups are enabled for sql instance', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automated backups are enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: 'testing-instance1',
                        instanceType: 'CLOUD_SQL_INSTANCE',
                        settings: {
                          tier: "db-custom-4-26624",
                          kind: "sql#settings",
                          backupConfiguration: {
                            startTime: "17:00",
                            kind: "sql#backupConfiguration",
                            location: "us",
                            backupRetentionSettings: {
                              retentionUnit: "COUNT",
                              retainedBackups: 7,
                            },
                            enabled: true,
                            binaryLogEnabled: true,
                            transactionLogRetentionDays: 7,
                          }
                        }
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if automated backups are not enabled for sql instance', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automated backups are not enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: 'testing-instance1',
                        instanceType: 'CLOUD_SQL_INSTANCE',
                        settings: {
                          tier: "db-custom-4-26624",
                          kind: "sql#settings",
                          backupConfiguration: {
                            startTime: "17:00",
                            kind: "sql#backupConfiguration",
                            location: "us",
                            backupRetentionSettings: {
                              retentionUnit: "COUNT",
                              retainedBackups: 7,
                            },
                            enabled: false,
                            binaryLogEnabled: true,
                            transactionLogRetentionDays: 7,
                          }
                        },
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});