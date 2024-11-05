const expect = require('chai').expect;
const tdeProtectorEncrypted = require('./tdeProtectorEncrypted');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
        "name": "test-server",
        "type": "Microsoft.Sql/servers"
    }
];

const managedInstances = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/managedInstances/test-instance", 
        "name": "test-instance",
        "type": "Microsoft.Sql/managedInstances"
    }
];

const byokEncryptionProtector = {
    "kind": "azurekeyvault",
    "serverKeyType": "AzureKeyVault",
    "uri": "https://test-vault.vault.azure.net/keys/test-key/123",
    "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/encryptionProtector/current"
};

const serviceEncryptionProtector = {
    "kind": "servicemanaged",
    "serverKeyType": "ServiceManaged",
    "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/encryptionProtector/current"
};

const createCache = (servers, serverEncryption, managedInstances, managedInstanceEncryption) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;
    const managedInstanceId = (managedInstances && managedInstances.length) ? managedInstances[0].id : null;
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: null,
                    data: servers
                }
            }
        },
        encryptionProtectors: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: null,
                        data: serverEncryption
                    }
                }
            }
        },
        managedInstances: {
            list: {
                'eastus': {
                    err: null,
                    data: managedInstances
                }
            }
        },
        managedInstanceEncryptionProtectors: {
            listByInstance: {
                'eastus': {
                    [managedInstanceId]: {
                        err: null,
                        data: managedInstanceEncryption
                    }
                }
            }
        }
    };
};

describe('tdeProtectorEncrypted', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers or managed instances found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('No managed instances found');
                done();
            };

            const cache = createCache([], null, [], null);
            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give passing result if no encryption protectors found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL Server Encryption Protectors found');
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('No Managed Instance Encryption Protectors found');
                done();
            };

            const cache = createCache(servers, [], managedInstances, []);
            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give failing result if TDE protector is not encrypted with BYOK', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Server TDE protector is not encrypted with BYOK');
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('SQL Server TDE protector is not encrypted with BYOK');
                done();
            };

            const cache = createCache(
                servers, [serviceEncryptionProtector],
                managedInstances, [serviceEncryptionProtector]
            );
            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give passing result if TDE protector is encrypted with BYOK', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Server TDE protector is encrypted with BYOK');
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('SQL Server TDE protector is encrypted with BYOK');
                done();
            };

            const cache = createCache(
                servers, [byokEncryptionProtector],
                managedInstances, [byokEncryptionProtector]
            );
            tdeProtectorEncrypted.run(cache, {}, callback);
        });

        it('should give passing result if TDE protector is encrypted with service-managed key when that is allowed', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Server TDE protector is encrypted with service-managed key');
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('SQL Server TDE protector is encrypted with service-managed key');
                done();
            };

            const cache = createCache(
                servers, [serviceEncryptionProtector],
                managedInstances, [serviceEncryptionProtector]
            );
            tdeProtectorEncrypted.run(cache, { sql_tde_protector_encryption_key: 'default' }, callback);
        });

        it('should give unknown result if unable to query SQL servers or managed instances', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[1].status).to.equal(3);
                expect(results[1].message).to.include('Unable to query for managed instances');
                done();
            };

            const cache = createCache(null, null, null, null);
            tdeProtectorEncrypted.run(cache, {}, callback);
        });
    });
});