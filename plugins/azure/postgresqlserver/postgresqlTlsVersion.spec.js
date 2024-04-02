var expect = require('chai').expect;
var postgresqlTlsVersion = require('./postgresqlTlsVersion');

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
        'minimalTlsVersion': 'TLS1_0',
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
        'minimalTlsVersion': 'TLS1_2',
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

describe('postgresqlTlsVersion', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const cache = createCache({});
            postgresqlTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No PostgreSQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if PostgreSQL Server is using TLS version less than desired TLS version', function(done) {
            const cache = createCache([listPostgres[0]]);
            postgresqlTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL server is not using TLS version 1.2');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if PostgreSQL Server is using TLS version equal to or higher than desired TLS version', function(done) {
            const cache = createCache([listPostgres[1]]);
            postgresqlTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL server is using TLS version 1.2 or higher');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        it('should give failing result if PostgreSQL Server allows all TLS versions', function(done) {
            const cache = createCache([listPostgres[2]]);
            postgresqlTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL server allows all TLS versions');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give UnKnown result if unable to query postgreSQL Server', function(done) {
            const cache = createCache(null);
            postgresqlTlsVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL servers: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        
    })
})