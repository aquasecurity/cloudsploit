var expect = require('chai').expect;
var tdeProtectorEncrypted = require('./tdeProtectorEncrypted');

const servers = [
    {
        "identity": {
          "principalId": "86c16ef5-51e9-4ecb-aeda-5844b8e8eca0",
          "type": "SystemAssigned",
          "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2"
        },
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/1234/resourceGroups/akhtar-rg/providers/Microsoft.Sql/servers/akhtar-server",
        "name": "akhtar-server",
        "type": "Microsoft.Sql/servers",
        "administratorLogin": "akhtar",
        "version": "12.0",
        "state": "Ready",
        "fullyQualifiedDomainName": "akhtar-server.database.windows.net",
        "privateEndpointConnections": [],
        "minimalTlsVersion": "1.2",
        "publicNetworkAccess": "Enabled"
      }
];

const encryptionProtectors = [
    {
        "kind": "azurekeyvault",
        "id": "/subscriptions/1234/resourceGroups/akhtar-rg/providers/Microsoft.Sql/servers/akhtar-server/encryptionProtector/current",
        "name": "current",
        "type": "Microsoft.Sql/servers/encryptionProtector",
        "serverKeyName": "sadeed-vault_sadeed-key_b5e783becb4a4e789dcd1239441d7567",
        "serverKeyType": "AzureKeyVault",
        "uri": "https://sadeed-vault.vault.azure.net/keys/sadeed-key/b5e783becb4a4e789dcd1239441d7567"
    },
    {
        "kind": "servicemanaged",
        "id": "/subscriptions/1234/resourceGroups/akhtar-rg/providers/Microsoft.Sql/servers/akhtar-server/encryptionProtector/current",
        "name": "current",
        "type": "Microsoft.Sql/servers/encryptionProtector",
        "serverKeyName": "ServiceManaged",
        "serverKeyType": "ServiceManaged"
    }
];

const createCache = (servers, encrypted, serversErr, encryptedErr) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: serversErr,
                    data: servers
                }
            }
        },
        encryptionProtectors: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: encryptedErr,
                        data: encrypted
                    }
                }
            }
        }
    }
};

describe('tdeProtectorEncrypted', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give passing result if No SQL Server Encryption Protectors found for server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL Server Encryption Protectors found for server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                []
            );

            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give failing result if SQL Server TDE protector is not encrypted with BYOK', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Server TDE protector is not encrypted with BYOK');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [encryptionProtectors[1]]
            );

            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give passing result if SQL Server TDE protector is encrypted with BYOK', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Server TDE protector is encrypted with BYOK');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [encryptionProtectors[0]]
            );

            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give unknown result if Unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [],
                { message: 'unable to query servers'}
            );

            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give unknown result if Unable to query for SQL Server Encryption Protectors', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL Server Encryption Protectors');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [],
                null,
                { message: 'Unable to query for Vulnerability Assessments setting'}
            );

            tdeProtectorEncrypted.run(cache, {}, callback);
        });
    })
});