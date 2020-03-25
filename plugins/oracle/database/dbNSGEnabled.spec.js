var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./dbNSGEnabled');

const createCache = (err, data) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        dbSystem: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('dbNSGEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a db system error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for database systems:')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['hello'],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no db systems are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No database systems found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if db systems do not have nsgs enabled.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The database system has network security groups disabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-1"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7a36nmivltthuqvwlbkkycv7rf7h75sjdziuym5vdqkjwo5hje4q",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": "Hostname oraclehello is already in-use in this subnet ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq. Please terminate & re-provision the instance with a non-overlapping hostname.",
                        "lifecycleState": "TERMINATED",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": null,
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": null,
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:40.542Z",
                        "timeZone": "UTC",
                        "version": null,
                        "vipIds": null
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-3"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7lonqrgxsl653pvr5hpbyms5ptvmv653sgvqvxdxo7qjhvnpn2ga",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": null,
                        "lifecycleState": "AVAILABLE",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": null,
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": "ocid1.vcndnsrecord.oc1.iad.abuwcljtvbjvzkqlfsgc4ig2cbybfz7wamzy274rs6otkdlelnvwnzz2tk5a",
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:39.153Z",
                        "timeZone": "UTC",
                        "version": "18.6.0.0.190416",
                        "vipIds": null
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if db systems have nsgs enabled.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All database systems have network security groups enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-1"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7a36nmivltthuqvwlbkkycv7rf7h75sjdziuym5vdqkjwo5hje4q",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": "Hostname oraclehello is already in-use in this subnet ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq. Please terminate & re-provision the instance with a non-overlapping hostname.",
                        "lifecycleState": "TERMINATED",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": null,
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": null,
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:40.542Z",
                        "timeZone": "UTC",
                        "version": null,
                        "vipIds": null
                    },
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "backupNetworkNsgIds": null,
                        "backupSubnetId": null,
                        "clusterName": null,
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "cpuCoreCount": 1,
                        "dataStoragePercentage": 80,
                        "dataStorageSizeInGBs": 256,
                        "databaseEdition": "ENTERPRISE_EDITION_HIGH_PERFORMANCE",
                        "dbSystemOptions": null,
                        "definedTags": {},
                        "diskRedundancy": "HIGH",
                        "displayName": "giodbsystemtest1",
                        "domain": "sub08061941230.giovcntest1.oraclevcn.com",
                        "faultDomains": [
                            "FAULT-DOMAIN-3"
                        ],
                        "freeformTags": {},
                        "hostname": "oraclehello",
                        "id": "ocid1.dbsystem.oc1.iad.abuwcljt7lonqrgxsl653pvr5hpbyms5ptvmv653sgvqvxdxo7qjhvnpn2ga",
                        "kmsKeyId": null,
                        "lastPatchHistoryEntryId": null,
                        "licenseModel": "LICENSE_INCLUDED",
                        "lifecycleDetails": null,
                        "lifecycleState": "AVAILABLE",
                        "listenerPort": 1521,
                        "nodeCount": 1,
                        "nsgIds": ['nsg1'],
                        "recoStorageSizeInGB": 256,
                        "scanDnsRecordId": "ocid1.vcndnsrecord.oc1.iad.abuwcljtvbjvzkqlfsgc4ig2cbybfz7wamzy274rs6otkdlelnvwnzz2tk5a",
                        "scanIpIds": null,
                        "shape": "VM.Standard2.1",
                        "sparseDiskgroup": null,
                        "sshPublicKeys": [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        ],
                        "subnetId": "ocid1.subnet.oc1.iad.aaaaaaaazwuooxeivkzmb622gwvlthykwalti333cdtjr7mdbrbtk6ybalhq",
                        "timeCreated": "2019-09-11T20:45:39.153Z",
                        "timeZone": "UTC",
                        "version": "18.6.0.0.190416",
                        "vipIds": null
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
    });
});