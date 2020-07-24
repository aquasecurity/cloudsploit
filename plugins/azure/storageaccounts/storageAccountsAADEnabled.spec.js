var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./storageAccountsAADEnabled');

const createCache = (err, list, get) => {
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        fileShares: {
            list: {
                'eastus': get
            }
        }

    }
};

describe('storageAccountsAADEnabled', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
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

        it('should give failing result if storage account is not configured with aad authentication', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Account is not configured with AAD Authentication');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Storage/storageAccounts/defaultactivitylogale920",
                        "name": "defaultactivitylogale920",
                        "type": "Microsoft.Storage/storageAccounts",
                        "tags": {},
                        "location": "eastus",
                        "sku": {
                            "name": "Standard_LRS",
                            "tier": "Standard"
                        },
                        "kind": "Storage",
                        "provisioningState": "Succeeded",
                        "primaryEndpoints": {
                            "blob": "https://defaultactivitylogale920.blob.core.windows.net/",
                            "queue": "https://defaultactivitylogale920.queue.core.windows.net/",
                            "table": "https://defaultactivitylogale920.table.core.windows.net/",
                            "file": "https://defaultactivitylogale920.file.core.windows.net/"
                        },
                        "primaryLocation": "eastus",
                        "statusOfPrimary": "available",
                        "creationTime": "2019-08-28T18:23:03.831Z",
                        "encryption": {
                            "services": {
                                "blob": {
                                    "enabled": true,
                                    "lastEnabledTime": "2019-08-28T18:23:03.909Z"
                                },
                                "file": {
                                    "enabled": true,
                                    "lastEnabledTime": "2019-08-28T18:23:03.909Z"
                                }
                            },
                            "keySource": "Microsoft.Storage"
                        },
                        "enableHttpsTrafficOnly": true,
                        "networkRuleSet": {
                            "bypass": "AzureServices",
                            "virtualNetworkRules": [],
                            "ipRules": [],
                            "defaultAction": "Allow"
                        }
                    }
                ],
                [
                    {
                        "entries": [],
                        "continuationToken": null,
                        "error": false,
                        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/test1/providers/Microsoft.Storage/storageAccounts/defaultactivitylogale920",
                        "location": "eastus",
                        "storageAccount": {
                            "name": "defaultactivitylogale920"
                        }
                    }
                ]

            );

            auth.run(cache, {}, callback);
        })

        it('should give passing result if storage account is not configured with aad authentication but no file shares', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account is not configured with AAD Authentication but no file shares are present');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Storage/storageAccounts/defaultactivitylogale920",
                        "name": "defaultactivitylogale920",
                        "type": "Microsoft.Storage/storageAccounts",
                        "tags": {},
                        "location": "eastus",
                        "sku": {
                            "name": "Standard_LRS",
                            "tier": "Standard"
                        },
                        "kind": "Storage",
                        "provisioningState": "Succeeded",
                        "primaryEndpoints": {
                            "blob": "https://defaultactivitylogale920.blob.core.windows.net/",
                            "queue": "https://defaultactivitylogale920.queue.core.windows.net/",
                            "table": "https://defaultactivitylogale920.table.core.windows.net/",
                            "file": "https://defaultactivitylogale920.file.core.windows.net/"
                        },
                        "primaryLocation": "eastus",
                        "statusOfPrimary": "available",
                        "creationTime": "2019-08-28T18:23:03.831Z",
                        "encryption": {
                            "services": {
                                "blob": {
                                    "enabled": true,
                                    "lastEnabledTime": "2019-08-28T18:23:03.909Z"
                                },
                                "file": {
                                    "enabled": true,
                                    "lastEnabledTime": "2019-08-28T18:23:03.909Z"
                                }
                            },
                            "keySource": "Microsoft.Storage"
                        },
                        "enableHttpsTrafficOnly": true,
                        "networkRuleSet": {
                            "bypass": "AzureServices",
                            "virtualNetworkRules": [],
                            "ipRules": [],
                            "defaultAction": "Allow"
                        }
                    }
                ],
                {
                    '/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Storage/storageAccounts/defaultactivitylogale920': {
                        data: []
                    }
                }
            );

            auth.run(cache, {storage_account_check_file_share: 'true'}, callback);
        })

        it('should give passing result if enabled App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Storage Account is configured with AAD Authentication');
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.Storage/storageAccounts/devstoragecloudsploit",
                        "name": "devstoragecloudsploit",
                        "type": "Microsoft.Storage/storageAccounts",
                        "tags": {
                            "environment": "dev"
                        },
                        "location": "eastus",
                        "sku": {
                            "name": "Standard_RAGRS",
                            "tier": "Standard"
                        },
                        "kind": "StorageV2",
                        "identity": {
                            "principalId": "6d5b910e-fac4-4181-bec1-fa36befeb672",
                            "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
                            "type": "SystemAssigned"
                        },
                        "provisioningState": "Succeeded",
                        "primaryEndpoints": {
                            "blob": "https://devstoragecloudsploit.blob.core.windows.net/",
                            "queue": "https://devstoragecloudsploit.queue.core.windows.net/",
                            "table": "https://devstoragecloudsploit.table.core.windows.net/",
                            "file": "https://devstoragecloudsploit.file.core.windows.net/",
                            "web": "https://devstoragecloudsploit.z13.web.core.windows.net/",
                            "dfs": "https://devstoragecloudsploit.dfs.core.windows.net/"
                        },
                        "primaryLocation": "eastus",
                        "statusOfPrimary": "available",
                        "secondaryLocation": "westus",
                        "statusOfSecondary": "available",
                        "creationTime": "2019-01-29T05:29:35.757Z",
                        "secondaryEndpoints": {
                            "blob": "https://devstoragecloudsploit-secondary.blob.core.windows.net/",
                            "queue": "https://devstoragecloudsploit-secondary.queue.core.windows.net/",
                            "table": "https://devstoragecloudsploit-secondary.table.core.windows.net/",
                            "web": "https://devstoragecloudsploit-secondary.z13.web.core.windows.net/",
                            "dfs": "https://devstoragecloudsploit-secondary.dfs.core.windows.net/"
                        },
                        "encryption": {
                            "services": {
                                "blob": {
                                    "enabled": true,
                                    "lastEnabledTime": "2019-01-29T05:29:35.914Z"
                                },
                                "file": {
                                    "enabled": true,
                                    "lastEnabledTime": "2019-01-29T05:29:35.914Z"
                                }
                            },
                            "keySource": "Microsoft.Keyvault",
                            "keyVaultProperties": {
                                "keyName": "byoktest1",
                                "keyVersion": "c6438177fd40462e81475318e33aff48",
                                "keyVaultUri": "https://giotestkeyvault.vault.azure.net"
                            }
                        },
                        "accessTier": "Hot",
                        "enableAzureFilesAadIntegration": true,
                        "enableHttpsTrafficOnly": false,
                        "networkRuleSet": {
                            "bypass": "AzureServices",
                            "virtualNetworkRules": [],
                            "ipRules": [],
                            "defaultAction": "Allow"
                        }
                    }
                ],
                [
                    {
                        "entries": [],
                        "continuationToken": null,
                        "error": false,
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/test1/providers/Microsoft.Storage/storageAccounts/devstoragecloudsploit",
                        "location": "eastus",
                        "storageAccount": {
                            "name": "devstoragecloudsploit"
                        }
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
})