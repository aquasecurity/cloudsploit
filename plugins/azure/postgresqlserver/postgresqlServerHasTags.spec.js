var expect = require('chai').expect;
var storage = require('./postgresqlServerHasTags');

const listPostgres = [
    {
        'sku': {
            'name': 'B_Gen5_1',
            'tier': 'Basic',
            'family': 'Gen5',
            'capacity': 1
        },
        'location': 'eastus',
        'tags': { "key": "value" },
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.DBforPostgreSQL/servers/server1',
        'name': 'server1',
        'type': 'Microsoft.DBforPostgreSQL/servers',
        'administratorLogin': 'Aquaadmin',
        'storageProfile': {
            'storageMB': 5120,
            'backupRetentionDays': 7,
            'geoRedundantBackup': 'Disabled',
            'storageAutogrow': 'Enabled'
        },
        'version': '11',
        'sslEnforcement': 'Enabled',
        'minimalTlsVersion': 'TLSEnforcementDisabled',
        'userVisibleState': 'Ready',
        'fullyQualifiedDomainName': 'server1.postgres.database.azure.com',
        'earliestRestoreDate': '2021-03-10T12:45:13.233+00:00',
        'replicationRole': '',
        'masterServerId': '',
        'byokEnforcement': 'Disabled',
        'privateEndpointConnections': [],
        'infrastructureEncryption': 'Disabled',
        'publicNetworkAccess': 'Enabled'
    },
    {
        'sku': {
            'name': 'B_Gen5_1',
            'tier': 'Basic',
            'family': 'Gen5',
            'capacity': 1
        },
        'location': 'eastus',
        'tags': {},
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.DBforPostgreSQL/servers/server1',
        'name': 'server1',
        'type': 'Microsoft.DBforPostgreSQL/servers',
        'administratorLogin': 'Aquaadmin',
        'storageProfile': {
            'storageMB': 5120,
            'backupRetentionDays': 7,
            'geoRedundantBackup': 'Disabled',
            'storageAutogrow': 'Disabled'
        },
        'version': '11',
        'sslEnforcement': 'Enabled',
        'minimalTlsVersion': 'TLSEnforcementDisabled',
        'userVisibleState': 'Ready',
        'fullyQualifiedDomainName': 'server1.postgres.database.azure.com',
        'earliestRestoreDate': '2021-03-10T12:45:13.233+00:00',
        'replicationRole': '',
        'masterServerId': '',
        'byokEnforcement': 'Disabled',
        'privateEndpointConnections': [],
        'infrastructureEncryption': 'Disabled',
        'publicNetworkAccess': 'Enabled'
    }
];

const createCache = (listPostgres) => {
    return {
        servers: {
            listPostgres: {
                'eastus': {
                    data: listPostgres
                }
            }
        }
    };
};

describe('postgresqlServerHasTags', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const cache = createCache({});
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL Servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if PostgreSQL Server does not have tags associated', function(done) {
            const cache = createCache([listPostgres[1]]);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL Server does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if PostgreSQL Server has tags associated', function(done) {
            const cache = createCache([listPostgres[0]]);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL Server has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        it('should give UnKnown result if unable to query postgreSQL Server', function(done) {
            const cache = createCache(null);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL Servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});