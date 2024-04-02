var expect = require('chai').expect;
var auth = require('./flexibleServerSCRAMEnabled');

const servers = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers"
    },
]

const configurations = [
    {
        id: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/meerab-rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/testfs/configurations/password_encryption',
        name: 'password_encryption',
        type: 'Microsoft.DBforPostgreSQL/flexibleServers/configurations',
        value: 'SCRAM-SHA-256',
        description: 'Determines the algorithm to use to encrypt the password..',
        defaultValue: 'md5',
        dataType: 'Enumeration',
        allowedValues: 'md5,scram-sha-256',
        source: 'user-override',
        isDynamicConfig: true,
        isReadOnly: false,
        isConfigPendingRestart: false
    },

    {
        id: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/meerab-rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/testfs/configurations/password_encryption',
        name: 'password_encryption',
        type: 'Microsoft.DBforPostgreSQL/flexibleServers/configurations',
        value: 'md5',
        description: 'Determines the algorithm to use to encrypt the password..',
        defaultValue: 'md5',
        dataType: 'Enumeration',
        allowedValues: 'md5,scram-sha-256',
        source: 'user-override',
        isDynamicConfig: true,
        isReadOnly: false,
        isConfigPendingRestart: false
    }

    
]

const createCache = (err, list, configuration) => {
    return {
        servers: {
            listPostgresFlexibleServer: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        flexibleServersConfigurations: {
            listByPostgresServer: {
                'eastus': configuration
            }
        }
    }
};

describe('flexibleServerSCRAMEnabled', function() {
    describe('run', function() {
        it('should PASS if no existing servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            auth.run(cache, {}, callback);
        });

        it('should give UNKNOWN if unable to query for PostgreSQL flexible Servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                null,
                {}
            );

            auth.run(cache, {}, callback);
        })

        it('should give UNKNOWN if unable to query for configurations', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                servers,
                {}
            );

            auth.run(cache, {}, callback);
        })

        it('should FAIL if PostgreSQL server is not using SCRAM', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL flexible server is not using SCRAM authentication protocol');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                servers,
                {
                    "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server": {
                        data: [configurations[1]]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        it('should PASS if PostgreSQL server is using SCRAM', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL flexible server is using SCRAM authentication protocol');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                servers,
                {
                    "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server": {
                        data: [configurations[0]]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        
    })
})