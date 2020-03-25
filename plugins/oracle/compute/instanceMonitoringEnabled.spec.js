var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceMonitoringEnabled');

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

        instance: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('instanceMonitoringEnabled', function () {
    describe('run', function () {
        it('should give unknown result if an instance error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for instances')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no instance records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No instances found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if instance monitoring is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Instance monitoring is enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "dedicatedVmHostId": null,
                        "definedTags": {},
                        "displayName": "inst-z0c5s-instance-pool-20190805-1436",
                        "extendedMetadata": {
                            "compute_management": {
                                "instance_configuration": {
                                    "state": "SUCCEEDED"
                                }
                            }
                        },
                        "faultDomain": "FAULT-DOMAIN-1",
                        "freeformTags": {
                            "oci:compute:instanceconfiguration": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaacsmqbsufpjlyzip2w4pvkbkgle2bsf6wkahxyuvonuqjlyckad5q",
                            "oci:compute:instancepool": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa"
                        },
                        "id": "ocid1.instance.oc1.iad.abuwcljtfqlmtwvynntlowy2qrboocmbfvsc5oz5r3bev7uabny7ehvxhiva",
                        "imageId": "ocid1.image.oc1.iad.aaaaaaaa5m7pxvywx2isnwon3o3kixkk6gq4tmdtfgvctj7xbl3wgo56uppa",
                        "ipxeScript": null,
                        "launchMode": "NATIVE",
                        "launchOptions": {
                            "bootVolumeType": "PARAVIRTUALIZED",
                            "firmware": "UEFI_64",
                            "networkType": "VFIO",
                            "remoteDataVolumeType": "PARAVIRTUALIZED",
                            "isPvEncryptionInTransitEnabled": true,
                            "isConsistentVolumeNamingEnabled": true
                        },
                        "lifecycleState": "RUNNING",
                        "metadata": {
                            "ssh_authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        },
                        "region": "iad",
                        "shape": "VM.Standard2.1",
                        "sourceDetails": {
                            "sourceType": "image",
                            "bootVolumeSizeInGBs": null,
                            "imageId": "ocid1.image.oc1.iad.aaaaaaaa5m7pxvywx2isnwon3o3kixkk6gq4tmdtfgvctj7xbl3wgo56uppa",
                            "kmsKeyId": null
                        },
                        "timeCreated": "2019-08-06T18:51:38.519Z",
                        "agentConfig": {
                            "isMonitoringDisabled": false,
                            "isManagementDisabled": null
                        },
                        "timeMaintenanceRebootDue": null,
                        "preferredMaintenanceAction": "REBOOT"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if instance monitoring is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Instance monitoring is disabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "availabilityDomain": "fMgC:US-ASHBURN-AD-1",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "dedicatedVmHostId": null,
                        "definedTags": {},
                        "displayName": "inst-z0c5s-instance-pool-20190805-1436",
                        "extendedMetadata": {
                            "compute_management": {
                                "instance_configuration": {
                                    "state": "SUCCEEDED"
                                }
                            }
                        },
                        "faultDomain": "FAULT-DOMAIN-1",
                        "freeformTags": {
                            "oci:compute:instanceconfiguration": "ocid1.instanceconfiguration.oc1.iad.aaaaaaaacsmqbsufpjlyzip2w4pvkbkgle2bsf6wkahxyuvonuqjlyckad5q",
                            "oci:compute:instancepool": "ocid1.instancepool.oc1.iad.aaaaaaaa3u3ku3miiz4cz7wpebecozqrvgdmymccqnmybhuc2uxgjettslfa"
                        },
                        "id": "ocid1.instance.oc1.iad.abuwcljtfqlmtwvynntlowy2qrboocmbfvsc5oz5r3bev7uabny7ehvxhiva",
                        "imageId": "ocid1.image.oc1.iad.aaaaaaaa5m7pxvywx2isnwon3o3kixkk6gq4tmdtfgvctj7xbl3wgo56uppa",
                        "ipxeScript": null,
                        "launchMode": "NATIVE",
                        "launchOptions": {
                            "bootVolumeType": "PARAVIRTUALIZED",
                            "firmware": "UEFI_64",
                            "networkType": "VFIO",
                            "remoteDataVolumeType": "PARAVIRTUALIZED",
                            "isPvEncryptionInTransitEnabled": true,
                            "isConsistentVolumeNamingEnabled": true
                        },
                        "lifecycleState": "RUNNING",
                        "metadata": {
                            "ssh_authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8SLjQgLYi9uR409mg0M46MMHcdTL5/GzPY2VDyw1cpljbPap0qEhx6SIkNQPw/Ka/mmdpLjFZatTduPFLBsZ2qMded1Kro4xGmFwCNfltz+CgSOcg6+eSO/luo9oAAQn7FTwkcTie0xQOL8hkeT1gM/1LkAdmc6Grqv5UkIdcUnKRvsQoJaofmYVsjGXAZF/d/LTFxyL2ZM/SXPOqzWAfNQtLLJ1BaPEWX0Ey36kUY/s5nGUIpZ/UBBL1jZd1yjZG2Pqf1qbwFbTzPKAtIS1XKKez5Dx4Y29Mi2Lx9gjRoZ0faO79DfWTRhUGC2PPUrJDmeWjoW4biLr1PCwuOl0L Gio@Gio's Macbook Pro"
                        },
                        "region": "iad",
                        "shape": "VM.Standard2.1",
                        "sourceDetails": {
                            "sourceType": "image",
                            "bootVolumeSizeInGBs": null,
                            "imageId": "ocid1.image.oc1.iad.aaaaaaaa5m7pxvywx2isnwon3o3kixkk6gq4tmdtfgvctj7xbl3wgo56uppa",
                            "kmsKeyId": null
                        },
                        "timeCreated": "2019-08-06T18:51:38.519Z",
                        "agentConfig": {
                            "isMonitoringDisabled": true,
                            "isManagementDisabled": null
                        },
                        "timeMaintenanceRebootDue": null,
                        "preferredMaintenanceAction": "REBOOT"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})