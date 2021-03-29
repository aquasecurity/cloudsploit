var expect = require('chai').expect;
var storage = require('./storageAutoGrowthEnabled');

const listPostgres = [
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

describe('storageAutoGrowth', function() {
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

        it('should give failing result if storage auto growth is not enabled for postgresql server', function(done) {
            const cache = createCache([listPostgres[1]]);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Auto Growth is not enabled for PostgreSQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if storage auto growth is enabled for postgresql server', function(done) {
            const cache = createCache([listPostgres[0]]);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Auto Growth is enabled for PostgreSQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});