var expect = require('chai').expect;
var plugin = require('./dbRestorable');

const createCache = (err, sqlInstances, backupRuns) => {
    return {
        instances: {
            sql: {
                list: {
                    'global': {
                        err: err,
                        data: sqlInstances
                    }
                }
            }
        },
        backupRuns: {            
            list: {
                'global': {
                    err: err,
                    data: backupRuns
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

describe('dbRestorable', function () {
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
        it('should give passing result if sql instance has backup available', function (done) {
            const callback = (err, results) => {
                console.log();
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance has backup available');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: "backup-testing"
                    }
                ],
                [
                    {
                        instance: "backup-testing"
                    }
                ]
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if sql instance does not have backups available', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL instance does not have backups available');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: "backup-testing"
                    }
                ],
                [
                ]
            );
            plugin.run(cache, {}, callback);
        });
    })
});