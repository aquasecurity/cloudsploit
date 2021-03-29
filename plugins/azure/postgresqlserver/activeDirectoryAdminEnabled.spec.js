var assert = require('assert');
var expect = require('chai').expect;
var activeDirectoryAdminEnabled = require('./activeDirectoryAdminEnabled');

const listPostgres = [
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/test-rg/providers/Microsoft.DBforPostgreSQL/servers/test-server",
    },
];

const serverAdministrators = [
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/test-rg/providers/Microsoft.DBforPostgreSQL/servers/test-server/administrators/ActiveDirectory",
        "name": "ActiveDirectory",
        "type": "PostgreSQL.Server.PAL",
        "administratorType": "ActiveDirectory",
        "login": "abc@cloudsploit.com"
    },
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/test-rg/providers/Microsoft.DBforPostgreSQL/servers/test-server/administrators/ActiveDirectory",
        "type": "PostgreSQL.Server.PAL",
        "administratorType": "ActiveDirectory",
        "login": "abc@cloudsploit.com"
    }
]
const createCache = (err, list, adlist, aderr) => {
    const id = (list && list.length) ? list[0].id : null;
    return {
        servers: {
            listPostgres: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        serverAdministrators: {
            list: {
                'eastus': {
                    [id]: {
                        err: aderr,
                        data: adlist
                    }
                }
            }
        }
    }
};

describe('activeDirectoryAdminEnabled', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL Servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            activeDirectoryAdminEnabled.run(cache, {}, callback);
        })

        it('should give failing result if Active Directory admin is not enabled on the PostgreSQL server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Active Directory admin is not enabled on the PostgreSQL server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                listPostgres,
                [serverAdministrators[1]]
            );

            activeDirectoryAdminEnabled.run(cache, {}, callback);
        });

        it('should give failing result if No Active Directory admin found for the server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No Active Directory admin found for the server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                listPostgres,
                []
            );

            activeDirectoryAdminEnabled.run(cache, {}, callback);
        });

        it('should give passing result if Active Directory admin is enabled on the PostgreSQL server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Active Directory admin is enabled on the PostgreSQL server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                listPostgres,
                [serverAdministrators[0]]
            );

            activeDirectoryAdminEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for PostgreSQL Servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL Servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [],
                { message: "Unable to list servers" },
            );

            activeDirectoryAdminEnabled.run(cache, {}, callback);
        });
    })
})