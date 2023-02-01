var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./mysqlFlexibleServersMinTls');

const createCache = (err, list, configuration) => {
    return {
        servers: {
            listMysqlFlexibleServer: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        flexibleServersConfigurations: {
            listByServer: {
                'eastus': configuration
            }
        }
    }
};

describe('mysqlFlexibleServersMinTls', function() {
    describe('run', function() {
        it('should PASS if no existing servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing MySQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            auth.run(cache, {}, callback);
        })

        it('should FAIL if MySQL server is not using TLSV1.2', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MySQL flexible server is not using latest TLS version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
                        "type": "Microsoft.DBforMySQL/flexibleServers"
                    }
                ],
                {
                    "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server": {
                        data: [
                            {
                                "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server/configurations/tls_version",
                                "value": "TLSV1",
                                "description": "Which protocols the server permits for encrypted connections. By default, TLS 1.2 is enforced",
                                "defaultValue": "TLSv1.2",
                                "dataType": "Set",
                                "allowedValues": "TLSv1,TLSv1.1,TLSv1.2",
                                "source": "user-override",
                                "isConfigPendingRestart": "False",
                                "isDynamicConfig": "False",
                                "isReadOnly": "False",
                                "name": "tls_version"
                            }
                        ]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        it('should PASS if MySQL server is using TLSV1.2', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MySQL flexible server is using latest TLS version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
                        "type": "Microsoft.DBforMySQL/flexibleServers"
                    }
                ],
                {
                    "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server": {
                        data: [
                            {
                                "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server/configurations/tls_version",
                                "value": "TLSV1.2",
                                "description": "Which protocols the server permits for encrypted connections. By default, TLS 1.2 is enforced",
                                "defaultValue": "TLSv1.2",
                                "dataType": "Set",
                                "allowedValues": "TLSv1,TLSv1.1,TLSv1.2",
                                "source": "user-override",
                                "isConfigPendingRestart": "False",
                                "isDynamicConfig": "False",
                                "isReadOnly": "False",
                                "name": "tls_version"
                            }
                        ]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

    })
})