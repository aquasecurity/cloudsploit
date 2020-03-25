var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./azureADAdminEnabled');

const createCache = (err, data, adata) => {
    return {
        servers: {
            sql: {
                list: {
                    'eastus': {
                        err: err,
                        data: data
                    }
                }
            }
        },
        serverAzureADAdministrators: {
            listByServer: {
                'eastus': {
                    err: err,
                    data: adata
                }
            }
        }
    }
};

describe('azureADAdminEnabled', function () {
    describe('run', function () {
        it('should give passing result if no sql servers', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No sql servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [],
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if disable App Service', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Active directory admin is not enabled on the following sql servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1",
                        "name": "giotestserver1",
                        "type": "Microsoft.Sql/servers",
                        "location": "eastus",
                        "tags": {
                            "environment": "dev"
                        },
                        "kind": "v12.0",
                        "administratorLogin": "gio",
                        "version": "12.0",
                        "state": "Ready",
                        "fullyQualifiedDomainName": "giotestserver1.database.windows.net",
                        "parameters": {
                            "resourceGroupName": "devresourcegroup",
                            "serverName": "giotestserver1"
                        },
                        "resourceGroupName": "devresourcegroup",
                        "resourceGroupId": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup",
                        "api": {
                            "AzureConfig": {
                                "ApplicationID": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                "KeyValue": "J9DcpOa-64BJ]DtUaVqux-BykYH[TFa4",
                                "DirectoryID": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                "SubscriptionID": "e79d9a03-3ab3-4481-bdcd-c5db1d55420a",
                                "location": "eastus",
                                "maxRetries": 5,
                                "retryDelayOptions": {
                                    "base": 300
                                },
                                "service": "serverAzureADAdministrators"
                            },
                            "credentials": {
                                "environment": {
                                    "validateAuthority": true,
                                    "name": "Azure",
                                    "portalUrl": "https://portal.azure.com",
                                    "publishingProfileUrl": "http://go.microsoft.com/fwlink/?LinkId=254432",
                                    "managementEndpointUrl": "https://management.core.windows.net",
                                    "resourceManagerEndpointUrl": "https://management.azure.com/",
                                    "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
                                    "sqlServerHostnameSuffix": ".database.windows.net",
                                    "galleryEndpointUrl": "https://gallery.azure.com/",
                                    "activeDirectoryEndpointUrl": "https://login.microsoftonline.com/",
                                    "activeDirectoryResourceId": "https://management.core.windows.net/",
                                    "activeDirectoryGraphResourceId": "https://graph.windows.net/",
                                    "batchResourceId": "https://batch.core.windows.net/",
                                    "activeDirectoryGraphApiVersion": "2013-04-05",
                                    "storageEndpointSuffix": ".core.windows.net",
                                    "keyVaultDnsSuffix": ".vault.azure.net",
                                    "azureDataLakeStoreFileSystemEndpointSuffix": "azuredatalakestore.net",
                                    "azureDataLakeAnalyticsCatalogAndJobEndpointSuffix": "azuredatalakeanalytics.net"
                                },
                                "authorizationScheme": "Bearer",
                                "tokenCache": {
                                    "_entries": [
                                        {
                                            "tokenType": "Bearer",
                                            "expiresIn": 3599,
                                            "expiresOn": "2019-10-29T23:46:49.353Z",
                                            "resource": "https://management.core.windows.net/",
                                            "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                            "isMRRT": true,
                                            "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                            "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                        }
                                    ]
                                },
                                "clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                "domain": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                "secret": "J9DcpOa-64BJ]DtUaVqux-BykYH[TFa4",
                                "context": {
                                    "_authority": {
                                        "_log": {
                                            "_componentName": "Authority",
                                            "_logContext": {
                                                "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                            }
                                        },
                                        "_url": {
                                            "protocol": "https:",
                                            "slashes": true,
                                            "auth": null,
                                            "host": "login.microsoftonline.com",
                                            "port": null,
                                            "hostname": "login.microsoftonline.com",
                                            "hash": null,
                                            "search": null,
                                            "query": null,
                                            "pathname": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                            "path": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                            "href": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                        },
                                        "_validated": true,
                                        "_host": "login.microsoftonline.com",
                                        "_tenant": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                        "_authorizationEndpoint": null,
                                        "_tokenEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/token",
                                        "_deviceCodeEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/devicecode",
                                        "_isAdfsAuthority": false,
                                        "_callContext": {
                                            "options": {},
                                            "_logContext": {
                                                "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                            }
                                        }
                                    },
                                    "_oauth2client": null,
                                    "_correlationId": null,
                                    "_callContext": {
                                        "options": {},
                                        "_logContext": {
                                            "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                        }
                                    },
                                    "_cache": {
                                        "_entries": [
                                            {
                                                "tokenType": "Bearer",
                                                "expiresIn": 3599,
                                                "expiresOn": "2019-10-29T23:46:49.353Z",
                                                "resource": "https://management.core.windows.net/",
                                                "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                                "isMRRT": true,
                                                "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                                "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                            }
                                        ]
                                    },
                                    "_tokenRequestWithUserCode": {}
                                }
                            },
                            "callObj": {
                                "api": "SQLManagementClient",
                                "reliesOnService": [
                                    "resourceGroups",
                                    "servers"
                                ],
                                "reliesOnSubService": [
                                    null,
                                    "sql"
                                ],
                                "reliesOnCall": [
                                    "list",
                                    "list"
                                ],
                                "filterKey": [
                                    "resourceGroupName",
                                    "serverName"
                                ],
                                "filterValue": [
                                    "resourceGroupName",
                                    "name"
                                ],
                                "arm": true
                            },
                            "callKey": "listByServer",
                            "location": "eastus",
                            "parameters": {
                                "resourceGroupName": "devresourcegroup",
                                "serverName": "giotestserver1"
                            },
                            "options": {},
                            "client": {
                                "userAgentInfo": {
                                    "value": [
                                        "Node/v8.11.4",
                                        "(x64-Darwin-18.7.0)",
                                        "ms-rest/2.5.0",
                                        "ms-rest-azure/2.6.0",
                                        "azure-arm-sql/5.7.0",
                                        "Azure-SDK-For-Node"
                                    ]
                                },
                                "acceptLanguage": "en-US",
                                "generateClientRequestId": true,
                                "longRunningOperationRetryTimeout": 30,
                                "baseUri": "https://management.azure.com",
                                "credentials": {
                                    "environment": {
                                        "validateAuthority": true,
                                        "name": "Azure",
                                        "portalUrl": "https://portal.azure.com",
                                        "publishingProfileUrl": "http://go.microsoft.com/fwlink/?LinkId=254432",
                                        "managementEndpointUrl": "https://management.core.windows.net",
                                        "resourceManagerEndpointUrl": "https://management.azure.com/",
                                        "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
                                        "sqlServerHostnameSuffix": ".database.windows.net",
                                        "galleryEndpointUrl": "https://gallery.azure.com/",
                                        "activeDirectoryEndpointUrl": "https://login.microsoftonline.com/",
                                        "activeDirectoryResourceId": "https://management.core.windows.net/",
                                        "activeDirectoryGraphResourceId": "https://graph.windows.net/",
                                        "batchResourceId": "https://batch.core.windows.net/",
                                        "activeDirectoryGraphApiVersion": "2013-04-05",
                                        "storageEndpointSuffix": ".core.windows.net",
                                        "keyVaultDnsSuffix": ".vault.azure.net",
                                        "azureDataLakeStoreFileSystemEndpointSuffix": "azuredatalakestore.net",
                                        "azureDataLakeAnalyticsCatalogAndJobEndpointSuffix": "azuredatalakeanalytics.net"
                                    },
                                    "authorizationScheme": "Bearer",
                                    "tokenCache": {
                                        "_entries": [
                                            {
                                                "tokenType": "Bearer",
                                                "expiresIn": 3599,
                                                "expiresOn": "2019-10-29T23:46:49.353Z",
                                                "resource": "https://management.core.windows.net/",
                                                "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                                "isMRRT": true,
                                                "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                                "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                            }
                                        ]
                                    },
                                    "clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                    "domain": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                    "secret": "J9DcpOa-64BJ]DtUaVqux-BykYH[TFa4",
                                    "context": {
                                        "_authority": {
                                            "_log": {
                                                "_componentName": "Authority",
                                                "_logContext": {
                                                    "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                                }
                                            },
                                            "_url": {
                                                "protocol": "https:",
                                                "slashes": true,
                                                "auth": null,
                                                "host": "login.microsoftonline.com",
                                                "port": null,
                                                "hostname": "login.microsoftonline.com",
                                                "hash": null,
                                                "search": null,
                                                "query": null,
                                                "pathname": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                                "path": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                                "href": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                            },
                                            "_validated": true,
                                            "_host": "login.microsoftonline.com",
                                            "_tenant": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                            "_authorizationEndpoint": null,
                                            "_tokenEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/token",
                                            "_deviceCodeEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/devicecode",
                                            "_isAdfsAuthority": false,
                                            "_callContext": {
                                                "options": {},
                                                "_logContext": {
                                                    "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                                }
                                            }
                                        },
                                        "_oauth2client": null,
                                        "_correlationId": null,
                                        "_callContext": {
                                            "options": {},
                                            "_logContext": {
                                                "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                            }
                                        },
                                        "_cache": {
                                            "_entries": [
                                                {
                                                    "tokenType": "Bearer",
                                                    "expiresIn": 3599,
                                                    "expiresOn": "2019-10-29T23:46:49.353Z",
                                                    "resource": "https://management.core.windows.net/",
                                                    "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                                    "isMRRT": true,
                                                    "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                                    "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                                }
                                            ]
                                        },
                                        "_tokenRequestWithUserCode": {}
                                    }
                                },
                                "subscriptionId": "e79d9a03-3ab3-4481-bdcd-c5db1d55420a",
                                "recoverableDatabases": {
                                    "client": "[Circular]"
                                },
                                "restorableDroppedDatabases": {
                                    "client": "[Circular]"
                                },
                                "servers": {
                                    "client": "[Circular]"
                                },
                                "serverConnectionPolicies": {
                                    "client": "[Circular]"
                                },
                                "databaseThreatDetectionPolicies": {
                                    "client": "[Circular]"
                                },
                                "dataMaskingPolicies": {
                                    "client": "[Circular]"
                                },
                                "dataMaskingRules": {
                                    "client": "[Circular]"
                                },
                                "firewallRules": {
                                    "client": "[Circular]"
                                },
                                "geoBackupPolicies": {
                                    "client": "[Circular]"
                                },
                                "databases": {
                                    "client": "[Circular]"
                                },
                                "elasticPools": {
                                    "client": "[Circular]"
                                },
                                "recommendedElasticPools": {
                                    "client": "[Circular]"
                                },
                                "replicationLinks": {
                                    "client": "[Circular]"
                                },
                                "serverAzureADAdministrators": {
                                    "client": "[Circular]"
                                },
                                "serverCommunicationLinks": {
                                    "client": "[Circular]"
                                },
                                "serviceObjectives": {
                                    "client": "[Circular]"
                                },
                                "elasticPoolActivities": {
                                    "client": "[Circular]"
                                },
                                "elasticPoolDatabaseActivities": {
                                    "client": "[Circular]"
                                },
                                "serviceTierAdvisors": {
                                    "client": "[Circular]"
                                },
                                "transparentDataEncryptions": {
                                    "client": "[Circular]"
                                },
                                "transparentDataEncryptionActivities": {
                                    "client": "[Circular]"
                                },
                                "serverUsages": {
                                    "client": "[Circular]"
                                },
                                "databaseUsages": {
                                    "client": "[Circular]"
                                },
                                "databaseAutomaticTuningOperations": {
                                    "client": "[Circular]"
                                },
                                "encryptionProtectors": {
                                    "client": "[Circular]"
                                },
                                "failoverGroups": {
                                    "client": "[Circular]"
                                },
                                "managedInstances": {
                                    "client": "[Circular]"
                                },
                                "operations": {
                                    "client": "[Circular]"
                                },
                                "serverKeys": {
                                    "client": "[Circular]"
                                },
                                "syncAgents": {
                                    "client": "[Circular]"
                                },
                                "syncGroups": {
                                    "client": "[Circular]"
                                },
                                "syncMembers": {
                                    "client": "[Circular]"
                                },
                                "subscriptionUsages": {
                                    "client": "[Circular]"
                                },
                                "virtualClusters": {
                                    "client": "[Circular]"
                                },
                                "virtualNetworkRules": {
                                    "client": "[Circular]"
                                },
                                "extendedDatabaseBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "extendedServerBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "serverBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "databaseBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "databaseVulnerabilityAssessmentRuleBaselines": {
                                    "client": "[Circular]"
                                },
                                "databaseVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "jobAgents": {
                                    "client": "[Circular]"
                                },
                                "jobCredentials": {
                                    "client": "[Circular]"
                                },
                                "jobExecutions": {
                                    "client": "[Circular]"
                                },
                                "jobs": {
                                    "client": "[Circular]"
                                },
                                "jobStepExecutions": {
                                    "client": "[Circular]"
                                },
                                "jobSteps": {
                                    "client": "[Circular]"
                                },
                                "jobTargetExecutions": {
                                    "client": "[Circular]"
                                },
                                "jobTargetGroups": {
                                    "client": "[Circular]"
                                },
                                "jobVersions": {
                                    "client": "[Circular]"
                                },
                                "longTermRetentionBackups": {
                                    "client": "[Circular]"
                                },
                                "backupLongTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "managedBackupShortTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "managedDatabases": {
                                    "client": "[Circular]"
                                },
                                "managedRestorableDroppedDatabaseBackupShortTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "serverAutomaticTuningOperations": {
                                    "client": "[Circular]"
                                },
                                "serverDnsAliases": {
                                    "client": "[Circular]"
                                },
                                "serverSecurityAlertPolicies": {
                                    "client": "[Circular]"
                                },
                                "restorableDroppedManagedDatabases": {
                                    "client": "[Circular]"
                                },
                                "restorePoints": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseSecurityAlertPolicies": {
                                    "client": "[Circular]"
                                },
                                "managedServerSecurityAlertPolicies": {
                                    "client": "[Circular]"
                                },
                                "sensitivityLabels": {
                                    "client": "[Circular]"
                                },
                                "databaseOperations": {
                                    "client": "[Circular]"
                                },
                                "elasticPoolOperations": {
                                    "client": "[Circular]"
                                },
                                "capabilities": {
                                    "client": "[Circular]"
                                },
                                "databaseVulnerabilityAssessmentScans": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseVulnerabilityAssessmentRuleBaselines": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseVulnerabilityAssessmentScans": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "instanceFailoverGroups": {
                                    "client": "[Circular]"
                                },
                                "backupShortTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "tdeCertificates": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceTdeCertificates": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceKeys": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceEncryptionProtectors": {
                                    "client": "[Circular]"
                                },
                                "recoverableManagedDatabases": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "serverVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseSensitivityLabels": {
                                    "client": "[Circular]"
                                },
                                "models": {}
                            }
                        }
                    }
                ],
                [

                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if enabled App Service', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Active directory admin is enabled on the sql server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1",
                        "name": "giotestserver1",
                        "type": "Microsoft.Sql/servers",
                        "location": "eastus",
                        "tags": {
                            "environment": "dev"
                        },
                        "kind": "v12.0",
                        "administratorLogin": "gio",
                        "version": "12.0",
                        "state": "Ready",
                        "fullyQualifiedDomainName": "giotestserver1.database.windows.net",
                        "parameters": {
                            "resourceGroupName": "devresourcegroup",
                            "serverName": "giotestserver1"
                        },
                        "resourceGroupName": "devresourcegroup",
                        "resourceGroupId": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup",
                        "api": {
                            "AzureConfig": {
                                "ApplicationID": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                "KeyValue": "J9DcpOa-64BJ]DtUaVqux-BykYH[TFa4",
                                "DirectoryID": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                "SubscriptionID": "e79d9a03-3ab3-4481-bdcd-c5db1d55420a",
                                "location": "eastus",
                                "maxRetries": 5,
                                "retryDelayOptions": {
                                    "base": 300
                                },
                                "service": "serverAzureADAdministrators"
                            },
                            "credentials": {
                                "environment": {
                                    "validateAuthority": true,
                                    "name": "Azure",
                                    "portalUrl": "https://portal.azure.com",
                                    "publishingProfileUrl": "http://go.microsoft.com/fwlink/?LinkId=254432",
                                    "managementEndpointUrl": "https://management.core.windows.net",
                                    "resourceManagerEndpointUrl": "https://management.azure.com/",
                                    "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
                                    "sqlServerHostnameSuffix": ".database.windows.net",
                                    "galleryEndpointUrl": "https://gallery.azure.com/",
                                    "activeDirectoryEndpointUrl": "https://login.microsoftonline.com/",
                                    "activeDirectoryResourceId": "https://management.core.windows.net/",
                                    "activeDirectoryGraphResourceId": "https://graph.windows.net/",
                                    "batchResourceId": "https://batch.core.windows.net/",
                                    "activeDirectoryGraphApiVersion": "2013-04-05",
                                    "storageEndpointSuffix": ".core.windows.net",
                                    "keyVaultDnsSuffix": ".vault.azure.net",
                                    "azureDataLakeStoreFileSystemEndpointSuffix": "azuredatalakestore.net",
                                    "azureDataLakeAnalyticsCatalogAndJobEndpointSuffix": "azuredatalakeanalytics.net"
                                },
                                "authorizationScheme": "Bearer",
                                "tokenCache": {
                                    "_entries": [
                                        {
                                            "tokenType": "Bearer",
                                            "expiresIn": 3599,
                                            "expiresOn": "2019-10-29T23:46:49.353Z",
                                            "resource": "https://management.core.windows.net/",
                                            "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                            "isMRRT": true,
                                            "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                            "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                        }
                                    ]
                                },
                                "clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                "domain": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                "secret": "J9DcpOa-64BJ]DtUaVqux-BykYH[TFa4",
                                "context": {
                                    "_authority": {
                                        "_log": {
                                            "_componentName": "Authority",
                                            "_logContext": {
                                                "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                            }
                                        },
                                        "_url": {
                                            "protocol": "https:",
                                            "slashes": true,
                                            "auth": null,
                                            "host": "login.microsoftonline.com",
                                            "port": null,
                                            "hostname": "login.microsoftonline.com",
                                            "hash": null,
                                            "search": null,
                                            "query": null,
                                            "pathname": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                            "path": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                            "href": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                        },
                                        "_validated": true,
                                        "_host": "login.microsoftonline.com",
                                        "_tenant": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                        "_authorizationEndpoint": null,
                                        "_tokenEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/token",
                                        "_deviceCodeEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/devicecode",
                                        "_isAdfsAuthority": false,
                                        "_callContext": {
                                            "options": {},
                                            "_logContext": {
                                                "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                            }
                                        }
                                    },
                                    "_oauth2client": null,
                                    "_correlationId": null,
                                    "_callContext": {
                                        "options": {},
                                        "_logContext": {
                                            "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                        }
                                    },
                                    "_cache": {
                                        "_entries": [
                                            {
                                                "tokenType": "Bearer",
                                                "expiresIn": 3599,
                                                "expiresOn": "2019-10-29T23:46:49.353Z",
                                                "resource": "https://management.core.windows.net/",
                                                "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                                "isMRRT": true,
                                                "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                                "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                            }
                                        ]
                                    },
                                    "_tokenRequestWithUserCode": {}
                                }
                            },
                            "callObj": {
                                "api": "SQLManagementClient",
                                "reliesOnService": [
                                    "resourceGroups",
                                    "servers"
                                ],
                                "reliesOnSubService": [
                                    null,
                                    "sql"
                                ],
                                "reliesOnCall": [
                                    "list",
                                    "list"
                                ],
                                "filterKey": [
                                    "resourceGroupName",
                                    "serverName"
                                ],
                                "filterValue": [
                                    "resourceGroupName",
                                    "name"
                                ],
                                "arm": true
                            },
                            "callKey": "listByServer",
                            "location": "eastus",
                            "parameters": {
                                "resourceGroupName": "devresourcegroup",
                                "serverName": "giotestserver1"
                            },
                            "options": {},
                            "client": {
                                "userAgentInfo": {
                                    "value": [
                                        "Node/v8.11.4",
                                        "(x64-Darwin-18.7.0)",
                                        "ms-rest/2.5.0",
                                        "ms-rest-azure/2.6.0",
                                        "azure-arm-sql/5.7.0",
                                        "Azure-SDK-For-Node"
                                    ]
                                },
                                "acceptLanguage": "en-US",
                                "generateClientRequestId": true,
                                "longRunningOperationRetryTimeout": 30,
                                "baseUri": "https://management.azure.com",
                                "credentials": {
                                    "environment": {
                                        "validateAuthority": true,
                                        "name": "Azure",
                                        "portalUrl": "https://portal.azure.com",
                                        "publishingProfileUrl": "http://go.microsoft.com/fwlink/?LinkId=254432",
                                        "managementEndpointUrl": "https://management.core.windows.net",
                                        "resourceManagerEndpointUrl": "https://management.azure.com/",
                                        "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
                                        "sqlServerHostnameSuffix": ".database.windows.net",
                                        "galleryEndpointUrl": "https://gallery.azure.com/",
                                        "activeDirectoryEndpointUrl": "https://login.microsoftonline.com/",
                                        "activeDirectoryResourceId": "https://management.core.windows.net/",
                                        "activeDirectoryGraphResourceId": "https://graph.windows.net/",
                                        "batchResourceId": "https://batch.core.windows.net/",
                                        "activeDirectoryGraphApiVersion": "2013-04-05",
                                        "storageEndpointSuffix": ".core.windows.net",
                                        "keyVaultDnsSuffix": ".vault.azure.net",
                                        "azureDataLakeStoreFileSystemEndpointSuffix": "azuredatalakestore.net",
                                        "azureDataLakeAnalyticsCatalogAndJobEndpointSuffix": "azuredatalakeanalytics.net"
                                    },
                                    "authorizationScheme": "Bearer",
                                    "tokenCache": {
                                        "_entries": [
                                            {
                                                "tokenType": "Bearer",
                                                "expiresIn": 3599,
                                                "expiresOn": "2019-10-29T23:46:49.353Z",
                                                "resource": "https://management.core.windows.net/",
                                                "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                                "isMRRT": true,
                                                "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                                "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                            }
                                        ]
                                    },
                                    "clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                    "domain": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                    "secret": "J9DcpOa-64BJ]DtUaVqux-BykYH[TFa4",
                                    "context": {
                                        "_authority": {
                                            "_log": {
                                                "_componentName": "Authority",
                                                "_logContext": {
                                                    "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                                }
                                            },
                                            "_url": {
                                                "protocol": "https:",
                                                "slashes": true,
                                                "auth": null,
                                                "host": "login.microsoftonline.com",
                                                "port": null,
                                                "hostname": "login.microsoftonline.com",
                                                "hash": null,
                                                "search": null,
                                                "query": null,
                                                "pathname": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                                "path": "/2d4f0836-5935-47f5-954c-14e713119ac2",
                                                "href": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                            },
                                            "_validated": true,
                                            "_host": "login.microsoftonline.com",
                                            "_tenant": "2d4f0836-5935-47f5-954c-14e713119ac2",
                                            "_authorizationEndpoint": null,
                                            "_tokenEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/token",
                                            "_deviceCodeEndpoint": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2/oauth2/devicecode",
                                            "_isAdfsAuthority": false,
                                            "_callContext": {
                                                "options": {},
                                                "_logContext": {
                                                    "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                                }
                                            }
                                        },
                                        "_oauth2client": null,
                                        "_correlationId": null,
                                        "_callContext": {
                                            "options": {},
                                            "_logContext": {
                                                "correlationId": "46b3543c-a5a2-4125-93eb-f20614da8a1a"
                                            }
                                        },
                                        "_cache": {
                                            "_entries": [
                                                {
                                                    "tokenType": "Bearer",
                                                    "expiresIn": 3599,
                                                    "expiresOn": "2019-10-29T23:46:49.353Z",
                                                    "resource": "https://management.core.windows.net/",
                                                    "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyIsImtpZCI6ImFQY3R3X29kdlJPb0VOZzNWb09sSWgydGlFcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8yZDRmMDgzNi01OTM1LTQ3ZjUtOTU0Yy0xNGU3MTMxMTlhYzIvIiwiaWF0IjoxNTcyMzg4OTEwLCJuYmYiOjE1NzIzODg5MTAsImV4cCI6MTU3MjM5MjgxMCwiYWlvIjoiNDJWZ1lQaXVlU3owYU82ajVEMTdLeXUvT0NzeEF3QT0iLCJhcHBpZCI6IjJhYzg4ZGJlLWU3ZTctNGYyOS1hM2U5LTg0NjNiOWIwOTQ0OSIsImFwcGlkYWNyIjoiMSIsImdyb3VwcyI6WyIzYWFhZjQ0My1lYjNjLTRmNDQtYTc5NS0xYTI3YTVkMTIyZTciXSwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMmQ0ZjA4MzYtNTkzNS00N2Y1LTk1NGMtMTRlNzEzMTE5YWMyLyIsIm9pZCI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInN1YiI6IjRkMmQ5ZDIzLTY3NjMtNGNhZC1hNzQyLTJhNTE2NTI0Yjc5YyIsInRpZCI6IjJkNGYwODM2LTU5MzUtNDdmNS05NTRjLTE0ZTcxMzExOWFjMiIsInV0aSI6IjZJVERBdHVkUWsyV3FhaWhOeDFzQUEiLCJ2ZXIiOiIxLjAifQ.kyNqWVEd3kSBNuxNojragsr3VI_xL80bYVXCsrGYponhdRorrpAONeB-N7G27Uke24kJ8_b0BR9dAFt0bj-3dGNqvlwg8dJtbFLLcsAcKlA1uL5cEEUt7-Ee_ySy1cFTYm0mte23iExIYerLTPyW0XJmnbdFiz27FJJEEQMr_9PT07HG05AHzweuhSfaVvQbYMEHfGsxxMBD3YwY-lWI-CyRBX3oWYIIwfYupIoj7XcC3tWNQHBbx1ZZBEsYAV7HD7K_m4mPEbS_0X3eND7nqZCNswVt3Zbycx2Vbco4un2dR6ankdKp1qWwRrzTLpkDlnA0tvIA3_jnEfxwD9XpKw",
                                                    "isMRRT": true,
                                                    "_clientId": "2ac88dbe-e7e7-4f29-a3e9-8463b9b09449",
                                                    "_authority": "https://login.microsoftonline.com/2d4f0836-5935-47f5-954c-14e713119ac2"
                                                }
                                            ]
                                        },
                                        "_tokenRequestWithUserCode": {}
                                    }
                                },
                                "subscriptionId": "e79d9a03-3ab3-4481-bdcd-c5db1d55420a",
                                "recoverableDatabases": {
                                    "client": "[Circular]"
                                },
                                "restorableDroppedDatabases": {
                                    "client": "[Circular]"
                                },
                                "servers": {
                                    "client": "[Circular]"
                                },
                                "serverConnectionPolicies": {
                                    "client": "[Circular]"
                                },
                                "databaseThreatDetectionPolicies": {
                                    "client": "[Circular]"
                                },
                                "dataMaskingPolicies": {
                                    "client": "[Circular]"
                                },
                                "dataMaskingRules": {
                                    "client": "[Circular]"
                                },
                                "firewallRules": {
                                    "client": "[Circular]"
                                },
                                "geoBackupPolicies": {
                                    "client": "[Circular]"
                                },
                                "databases": {
                                    "client": "[Circular]"
                                },
                                "elasticPools": {
                                    "client": "[Circular]"
                                },
                                "recommendedElasticPools": {
                                    "client": "[Circular]"
                                },
                                "replicationLinks": {
                                    "client": "[Circular]"
                                },
                                "serverAzureADAdministrators": {
                                    "client": "[Circular]"
                                },
                                "serverCommunicationLinks": {
                                    "client": "[Circular]"
                                },
                                "serviceObjectives": {
                                    "client": "[Circular]"
                                },
                                "elasticPoolActivities": {
                                    "client": "[Circular]"
                                },
                                "elasticPoolDatabaseActivities": {
                                    "client": "[Circular]"
                                },
                                "serviceTierAdvisors": {
                                    "client": "[Circular]"
                                },
                                "transparentDataEncryptions": {
                                    "client": "[Circular]"
                                },
                                "transparentDataEncryptionActivities": {
                                    "client": "[Circular]"
                                },
                                "serverUsages": {
                                    "client": "[Circular]"
                                },
                                "databaseUsages": {
                                    "client": "[Circular]"
                                },
                                "databaseAutomaticTuningOperations": {
                                    "client": "[Circular]"
                                },
                                "encryptionProtectors": {
                                    "client": "[Circular]"
                                },
                                "failoverGroups": {
                                    "client": "[Circular]"
                                },
                                "managedInstances": {
                                    "client": "[Circular]"
                                },
                                "operations": {
                                    "client": "[Circular]"
                                },
                                "serverKeys": {
                                    "client": "[Circular]"
                                },
                                "syncAgents": {
                                    "client": "[Circular]"
                                },
                                "syncGroups": {
                                    "client": "[Circular]"
                                },
                                "syncMembers": {
                                    "client": "[Circular]"
                                },
                                "subscriptionUsages": {
                                    "client": "[Circular]"
                                },
                                "virtualClusters": {
                                    "client": "[Circular]"
                                },
                                "virtualNetworkRules": {
                                    "client": "[Circular]"
                                },
                                "extendedDatabaseBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "extendedServerBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "serverBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "databaseBlobAuditingPolicies": {
                                    "client": "[Circular]"
                                },
                                "databaseVulnerabilityAssessmentRuleBaselines": {
                                    "client": "[Circular]"
                                },
                                "databaseVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "jobAgents": {
                                    "client": "[Circular]"
                                },
                                "jobCredentials": {
                                    "client": "[Circular]"
                                },
                                "jobExecutions": {
                                    "client": "[Circular]"
                                },
                                "jobs": {
                                    "client": "[Circular]"
                                },
                                "jobStepExecutions": {
                                    "client": "[Circular]"
                                },
                                "jobSteps": {
                                    "client": "[Circular]"
                                },
                                "jobTargetExecutions": {
                                    "client": "[Circular]"
                                },
                                "jobTargetGroups": {
                                    "client": "[Circular]"
                                },
                                "jobVersions": {
                                    "client": "[Circular]"
                                },
                                "longTermRetentionBackups": {
                                    "client": "[Circular]"
                                },
                                "backupLongTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "managedBackupShortTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "managedDatabases": {
                                    "client": "[Circular]"
                                },
                                "managedRestorableDroppedDatabaseBackupShortTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "serverAutomaticTuningOperations": {
                                    "client": "[Circular]"
                                },
                                "serverDnsAliases": {
                                    "client": "[Circular]"
                                },
                                "serverSecurityAlertPolicies": {
                                    "client": "[Circular]"
                                },
                                "restorableDroppedManagedDatabases": {
                                    "client": "[Circular]"
                                },
                                "restorePoints": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseSecurityAlertPolicies": {
                                    "client": "[Circular]"
                                },
                                "managedServerSecurityAlertPolicies": {
                                    "client": "[Circular]"
                                },
                                "sensitivityLabels": {
                                    "client": "[Circular]"
                                },
                                "databaseOperations": {
                                    "client": "[Circular]"
                                },
                                "elasticPoolOperations": {
                                    "client": "[Circular]"
                                },
                                "capabilities": {
                                    "client": "[Circular]"
                                },
                                "databaseVulnerabilityAssessmentScans": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseVulnerabilityAssessmentRuleBaselines": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseVulnerabilityAssessmentScans": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "instanceFailoverGroups": {
                                    "client": "[Circular]"
                                },
                                "backupShortTermRetentionPolicies": {
                                    "client": "[Circular]"
                                },
                                "tdeCertificates": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceTdeCertificates": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceKeys": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceEncryptionProtectors": {
                                    "client": "[Circular]"
                                },
                                "recoverableManagedDatabases": {
                                    "client": "[Circular]"
                                },
                                "managedInstanceVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "serverVulnerabilityAssessments": {
                                    "client": "[Circular]"
                                },
                                "managedDatabaseSensitivityLabels": {
                                    "client": "[Circular]"
                                },
                                "models": {}
                            }
                        }
                    }
                ],
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1/administrators/ActiveDirectory",
                        "name": "ActiveDirectory",
                        "type": "Microsoft.Sql/servers/administrators",
                        "administratorType": "ActiveDirectory",
                        "login": "giovanni@cloudsploit.com",
                        "sid": "3fc56a96-2173-49c5-b915-08886e7fafa3",
                        "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
                        "location": "eastus",
                        "storageAccount": {
                            "name": "giotestserver1"
                        }
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
})