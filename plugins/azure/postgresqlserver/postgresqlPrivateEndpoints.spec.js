var expect = require('chai').expect;
var privateEndpoints = require('./postgresqlPrivateEndpoints');

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
        'administratorLogin': 'test',
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
        'administratorLogin': 'test',
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
        'privateEndpointConnections': [
            {
                'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/privateEndpointConnections/test-endpoint',
                'provisioningState': 'Ready'
            }
        ],
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

describe('privateEndpoints', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const cache = createCache({});
            privateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No PostgreSQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if private endpoints are not configured', function(done) {
            const cache = createCache([listPostgres[0]]);
            privateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Private Endpoints are not configured for the PostgreSQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give should give passing result if private endpoints are configured', function(done) {
            const cache = createCache([listPostgres[1]]);
            privateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private Endpoints are configured for the PostgreSQL Server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give UnKnown result if unable to query postgreSQL Server', function(done) {
            const cache = createCache(null);
            privateEndpoints.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL servers: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        
    })
})