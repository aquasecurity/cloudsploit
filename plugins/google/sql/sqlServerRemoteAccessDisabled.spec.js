var expect = require('chai').expect;
var plugin = require('./sqlServerRemoteAccessDisabled');

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

describe('sqlServerRemoteAccessDisabled', function () {
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

        it('should give passing result if sql instance database type is not of SQL Server type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance database type is not of SQL Server type');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    name: "testing-instance",
                    databaseVersion: "MYSQL_5_7",
                }],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if sql instance does not have remote access flag enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance does not have "remote access" flag enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "SQLSERVER_2019_STANDARD",
                    settings: {
                      databaseFlags: [
                        {
                            name: "remote access",
                            value: "off",
                        },
                      ]}
                }],
            );
            
            plugin.run(cache, {}, callback);
        });
       
        it('should give failing result if sql instance has remote access flag enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL instance has "remote access" flag enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "SQLSERVER_2019_STANDARD",
                    settings: {
                      databaseFlags: [
                        {
                            name: "remote access",
                            value: "on",
                        },
                      ]}
                }],
            );

            plugin.run(cache, {}, callback);
        });
    })
})